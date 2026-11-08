-- Starforge M6: per-repository CI dependency cache entries.
-- Keep in lockstep with ../sqlite/0044_ci_cache.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

CREATE TABLE ci_cache_entries (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    blake3 TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    UNIQUE (repo_id, key)
);
CREATE INDEX ci_cache_entries_repo_expiry ON ci_cache_entries (repo_id, expires_at);
