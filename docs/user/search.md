# Search

The search page (`/search`, with a search box in the site header) has
Trails and Sessions tabs, and each repository has its own code search
(`/{owner}/{repo}/search`, with a search field on every repository
page). Every search page and every session search response sends
`X-Robots-Tag: noindex` (spec §11.1).

**What is indexed.** One Tantivy index (the only crate that depends on
it is `starforged-index`) holds Trail documents — one per Trail, keyed
`trail_id`, with the title and the intent plus all comment bodies — and
session event documents — one per searchable event, keyed
`session_id` + `seq`, with user and assistant message text, tool names,
and file paths. Reasoning, system and compaction events, tool call
inputs and outputs, and review comments are deliberately **not**
indexed: they are large and secret-prone, and the document content
comes from the same reader the session viewer uses (with redaction
applied), so the index never holds text the viewer would redact. Only
`complete` sessions are indexed — a receiving session becomes
searchable when it completes. The index lives under
`storage.index_dir` (default `index` inside `storage.data_dir`,
`STARFORGE__STORAGE__INDEX_DIR` to override), is rebuildable from the
database and blobs, and is skipped by backups; a missing or corrupt
index is recreated empty at startup and a full rebuild job is
enqueued — the server never refuses to start because of the index.
Indexing never blocks or fails a mutation: mutations only enqueue
index jobs (de-duplicated by kind and id), and purging or deleting a
session drops its documents.

**Filters.** Trail and session search share `q`, `repo` (`owner/name`),
`author` (a handle), `from`/`to` (RFC 3339 date or date-time,
inclusive), `page` (1-based), and `per_page` (at most 50, default
20); session search adds `agent`, `model` (a term of the session's
models), and `commit` (a full or ≥7-character SHA prefix, matched
against the session's linked commits). A Trail's date is its
`updated_at`; an event's is its own timestamp. Session results group
events by session — each result shows the session and its
best-matching events (at most three snippets) and links to the viewer
at `#turn-<seq>`. An invalid date, SHA, `page`, `per_page`, or
malformed `repo` answers `422`; an unknown `repo` or `author` filter
answers an empty page, so existence stays undiscoverable.

**Permissions.** The index is never the source of truth. The query
carries a permission filter (public repositories, internal ones for
signed-in viewers, and the private/internal repositories the viewer
can read through grants, org and team grants, or site administration),
and every hit is re-read from the database and re-checked before it is
returned — Trail hits need repository read, session hits must still
pass the §6.4 session read rule (unpublished sessions on public
repositories need membership; quarantined sessions are uploader or
repo-admin only; site admins read everything). A stale document can
only ever hide a result, never leak one: a repository that became
private, a revoked grant, a deleted repository, a session quarantined
or unpublished after indexing — all hide the hit immediately, with no
index job run needed. Quarantined sessions **are** indexed (with
their quarantine state) so the uploader and admins can find them; the
filter and re-check hide them from everyone else. Archived
repositories stay searchable (only pushes refuse them). A
repository the viewer cannot read answers `404` on code search, never
`403`.

**Code search** runs `git grep` over the default branch's tip commit
only — a match that exists on another branch is absent. The query is
a fixed string (regex metacharacters are literal, and a query starting
with `-` is searched literally, never treated as an option) with an
optional case-insensitive switch (`case=insensitive`), refuses an
empty query or one longer than 256 characters, times out after 10 s,
skips binary files, and returns at most 200 matches over at most 50
files with lines truncated to 500 characters (`truncated: true` when
either cap bites). Each match links to the file and line
(`/{owner}/{repo}/blob/{ref}/{path}#L{line}`). An empty repository
answers an empty result.

**Rebuilding the index.** `starforged index rebuild` (server stopped)
wipes and rebuilds the index from the database and blobs and prints
the counts (`index rebuild complete: N trail(s), M event(s)`); while
the server runs it refuses with a "stop the server or use the admin
rebuild" message. While the server runs, site admins can instead use
the **Rebuild search index** action on the admin jobs page
(`/admin/jobs`, CSRF-protected, site-admin only, audited as
`index.rebuild`), which enqueues the same rebuild as a background job.

**API.** `GET /api/v1/search/trails?q=&repo=&author=&from=&to=&page=&per_page=`
returns `{"results": [{"repo", "number", "title", "state",
"updated_at", "snippet": {"text", "highlights": [[start, end]…]}}],
"page", "per_page", "has_more"}`; `GET /api/v1/search/sessions` with
the session filters returns the grouped sessions with their matched
events (`seq`, `kind`, `snippet`); and
`GET /api/v1/repos/{owner}/{repo}/search/code?q=&case=sensitive|insensitive`
returns `{"ref", "commit", "matches": [{"path", "line", "text"}],
"truncated"}`. Anonymous callers are allowed; a token must carry
`repo:read` (a token without it answers `403`).
