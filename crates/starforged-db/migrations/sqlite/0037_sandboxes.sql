-- Starforge M6b: sandboxes and sandbox usage (provider control plane).
-- Keep in lockstep with ../postgres/0037_sandboxes.sql.
--
-- `sandboxes` records one sandbox created through the API: the provider
-- handle (`external_id`), the plan columns (`runtime`, `template`, cpu /
-- mem / disk), the idempotency key (unique per owner so a retried create
-- returns the same sandbox), and the per-sandbox CA fingerprint. `job_id`
-- links a CI job's sandbox (nullable for interactive sandboxes).
-- `metadata` is TEXT holding JSON (no JSON operators — both engines).
-- `sandbox_usage` meters sandbox-seconds per owner/repo in hourly windows
-- (`window_start` is the window's unix start) for the seconds/hour quota.

CREATE TABLE sandboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL DEFAULT 'local',
    runtime TEXT NOT NULL DEFAULT 'podman',
    external_id TEXT NOT NULL DEFAULT '',
    job_id INTEGER REFERENCES ci_jobs (id) ON DELETE SET NULL,
    owner_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'creating' CHECK (state IN ('creating', 'running', 'paused', 'killed', 'error')),
    template TEXT NOT NULL DEFAULT '',
    cpu REAL NOT NULL DEFAULT 0,
    mem_mb INTEGER NOT NULL DEFAULT 0,
    disk_gb INTEGER NOT NULL DEFAULT 0,
    idempotency_key TEXT,
    ca_fingerprint TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER
);
CREATE UNIQUE INDEX sandboxes_owner_idempotency ON sandboxes (owner_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX sandboxes_state_expires ON sandboxes (state, expires_at);
CREATE INDEX sandboxes_job ON sandboxes (job_id);
CREATE INDEX sandboxes_owner_state ON sandboxes (owner_id, state);
CREATE INDEX sandboxes_repo_state ON sandboxes (repo_id, state);

CREATE TABLE sandbox_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    window_start INTEGER NOT NULL,
    seconds INTEGER NOT NULL DEFAULT 0 CHECK (seconds >= 0),
    created_at INTEGER NOT NULL
);
CREATE INDEX sandbox_usage_owner_window ON sandbox_usage (owner_id, window_start);
CREATE INDEX sandbox_usage_repo_window ON sandbox_usage (repo_id, window_start);
