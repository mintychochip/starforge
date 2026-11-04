-- Starforge M1d: session ingest schema (sessions, segments, commit_links, blobs).
-- Keep in lockstep with ../sqlite/0008_sessions.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

ALTER TABLE repos ADD COLUMN redact_rules TEXT NOT NULL DEFAULT '';

CREATE TABLE sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    ulid TEXT NOT NULL,
    uploader_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    agent_name TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    models TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT '',
    head_sha TEXT NOT NULL DEFAULT '',
    started_at BIGINT NOT NULL DEFAULT 0,
    ended_at BIGINT,
    parent_ulid TEXT,
    usage_input BIGINT NOT NULL DEFAULT 0,
    usage_output BIGINT NOT NULL DEFAULT 0,
    usage_cache_read BIGINT NOT NULL DEFAULT 0,
    usage_cache_write BIGINT NOT NULL DEFAULT 0,
    usage_reasoning BIGINT NOT NULL DEFAULT 0,
    files_touched TEXT NOT NULL DEFAULT '',
    turn_count BIGINT NOT NULL DEFAULT 0,
    tool_call_count BIGINT NOT NULL DEFAULT 0,
    lifecycle TEXT NOT NULL DEFAULT 'receiving' CHECK (lifecycle IN ('receiving', 'complete')),
    quarantine TEXT NOT NULL DEFAULT 'none' CHECK (quarantine IN ('none', 'quarantined', 'released')),
    quarantine_reason TEXT NOT NULL DEFAULT '',
    quarantine_detail TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'inherit' CHECK (visibility IN ('inherit', 'published')),
    raw_enabled BIGINT NOT NULL DEFAULT 0,
    redaction_fingerprint TEXT NOT NULL DEFAULT '',
    redaction_counts TEXT NOT NULL DEFAULT '',
    capture_mode TEXT NOT NULL DEFAULT '',
    cli_version TEXT NOT NULL DEFAULT '',
    adapter_verified BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (repo_id, ulid)
);
CREATE INDEX sessions_repo ON sessions (repo_id);
CREATE INDEX sessions_uploader ON sessions (uploader_id);
CREATE INDEX sessions_quarantine ON sessions (repo_id, quarantine);

CREATE TABLE segments (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    n BIGINT NOT NULL,
    seq_start BIGINT NOT NULL,
    seq_end BIGINT NOT NULL,
    blob_hash TEXT NOT NULL,
    byte_size BIGINT NOT NULL,
    raw_blob_hash TEXT,
    uploaded_at BIGINT NOT NULL,
    UNIQUE (session_id, n)
);
CREATE INDEX segments_session ON segments (session_id);

CREATE TABLE commit_links (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    session_ulid TEXT NOT NULL,
    session_id BIGINT REFERENCES sessions (id) ON DELETE CASCADE,
    sha TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'trailer' CHECK (source IN ('trailer', 'cli_claim')),
    confidence TEXT NOT NULL DEFAULT 'heuristic' CHECK (confidence IN ('exact', 'heuristic')),
    seq_start BIGINT,
    seq_end BIGINT,
    trailer_seen BIGINT NOT NULL DEFAULT 0,
    claim_seen BIGINT NOT NULL DEFAULT 0,
    UNIQUE (repo_id, session_ulid, sha)
);
CREATE INDEX commit_links_session ON commit_links (session_id);
CREATE INDEX commit_links_repo_sha ON commit_links (repo_id, sha);

CREATE TABLE blobs (
    hash TEXT PRIMARY KEY,
    size BIGINT NOT NULL,
    refcount BIGINT NOT NULL DEFAULT 0,
    backend_key TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
