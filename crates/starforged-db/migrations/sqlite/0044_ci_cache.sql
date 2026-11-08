-- Starforge M6: per-repository CI dependency cache entries.
-- Keep in lockstep with ../postgres/0044_ci_cache.sql.
--
-- One row per (repository, exact key). The bytes live in the shared
-- content-addressed blob store and `blake3` names them. `restore_keys` are
-- prefixes matched against `key`; `last_used_at` drives LRU eviction and
-- `expires_at` the retention window.

CREATE TABLE ci_cache_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    blake3 TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    UNIQUE (repo_id, key)
);
CREATE INDEX ci_cache_entries_repo_expiry ON ci_cache_entries (repo_id, expires_at);
