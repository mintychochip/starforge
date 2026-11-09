-- Starforge: scope CI caches to the job's branch and record the job branch.
-- Keep in lockstep with ../postgres/0045_ci_cache_scope.sql.
--
-- A cache entry is keyed by (repository, branch scope, key). A job reads its
-- own branch's entry and then the default branch's; it writes only its own.
-- This keeps a feature-branch or Trail job from poisoning a cache that a
-- default-branch job restores and executes.

ALTER TABLE ci_jobs ADD COLUMN branch TEXT NOT NULL DEFAULT '';

CREATE TABLE ci_cache_entries_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    scope TEXT NOT NULL DEFAULT '',
    key TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    blake3 TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    UNIQUE (repo_id, scope, key)
);
INSERT INTO ci_cache_entries_new
    (id, repo_id, scope, key, size, blake3, created_at, last_used_at, expires_at)
    SELECT id, repo_id, '', key, size, blake3, created_at, last_used_at, expires_at
    FROM ci_cache_entries;
DROP TABLE ci_cache_entries;
ALTER TABLE ci_cache_entries_new RENAME TO ci_cache_entries;
CREATE INDEX ci_cache_entries_repo_expiry ON ci_cache_entries (repo_id, expires_at);
