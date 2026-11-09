-- Starforge: scope CI caches to the job's branch and record the job branch.
-- Keep in lockstep with ../sqlite/0045_ci_cache_scope.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

ALTER TABLE ci_jobs ADD COLUMN branch TEXT NOT NULL DEFAULT '';

CREATE TABLE ci_cache_entries_new (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    scope TEXT NOT NULL DEFAULT '',
    key TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    blake3 TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    UNIQUE (repo_id, scope, key)
);
INSERT INTO ci_cache_entries_new
    (id, repo_id, scope, key, size, blake3, created_at, last_used_at, expires_at)
    OVERRIDING SYSTEM VALUE
    SELECT id, repo_id, '', key, size, blake3, created_at, last_used_at, expires_at
    FROM ci_cache_entries;
SELECT setval(
    pg_get_serial_sequence('ci_cache_entries', 'id'),
    COALESCE((SELECT MAX(id) FROM ci_cache_entries), 0) + 1,
    false
);
DROP TABLE ci_cache_entries;
ALTER TABLE ci_cache_entries_new RENAME TO ci_cache_entries;
CREATE INDEX ci_cache_entries_repo_expiry ON ci_cache_entries (repo_id, expires_at);
