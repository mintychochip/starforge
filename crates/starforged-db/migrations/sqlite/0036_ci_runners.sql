-- Starforge M6-0: opt-in self-hosted CI runners (control plane only).
-- Keep in lockstep with ../postgres/0036_ci_runners.sql.
--
-- Token columns store SHA-256 hashes only; plaintext tokens are shown once
-- at mint/registration time and never stored. `labels` and ci_jobs `spec`
-- are TEXT holding JSON (no JSON operators — both engines). `ci_jobs` is a
-- separate queue from the internal `jobs` table: it carries a per-claim
-- `lease_token` fence (decision 13). `git_token_id` links the short-lived
-- git credential minted for the job (access_tokens) so finish/cancel can
-- revoke it. `ci_jobs` is created before the `sessions` ALTER below.

CREATE TABLE runners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL,
    token_hint TEXT NOT NULL DEFAULT '',
    labels TEXT NOT NULL DEFAULT '[]',
    ephemeral INTEGER NOT NULL DEFAULT 0,
    paused INTEGER NOT NULL DEFAULT 0,
    max_concurrent INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrent >= 1),
    version TEXT NOT NULL DEFAULT '',
    last_seen_at INTEGER,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX runners_repo ON runners (repo_id);
CREATE UNIQUE INDEX runners_token_hash ON runners (token_hash);

CREATE TABLE runner_registration_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    labels TEXT NOT NULL DEFAULT '[]',
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX runner_registration_tokens_hash ON runner_registration_tokens (token_hash);
CREATE INDEX runner_registration_tokens_repo ON runner_registration_tokens (repo_id);

CREATE TABLE ci_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    trail_id INTEGER REFERENCES trails (id) ON DELETE CASCADE,
    change_id INTEGER REFERENCES changes (id) ON DELETE CASCADE,
    revision_id INTEGER REFERENCES revisions (id) ON DELETE CASCADE,
    commit_sha TEXT NOT NULL,
    base_sha TEXT,
    job_name TEXT NOT NULL,
    spec TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'claimed', 'running', 'succeeded', 'failed', 'canceled')),
    runner_id INTEGER REFERENCES runners (id) ON DELETE SET NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    run_at INTEGER NOT NULL,
    lease_until INTEGER,
    lease_token TEXT,
    deadline INTEGER NOT NULL,
    exit_code INTEGER,
    checksum TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    git_token_id INTEGER REFERENCES access_tokens (id) ON DELETE SET NULL,
    last_error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER
);
CREATE INDEX ci_jobs_state_run_at ON ci_jobs (state, run_at);
CREATE INDEX ci_jobs_repo_commit ON ci_jobs (repo_id, commit_sha);
CREATE INDEX ci_jobs_runner_state ON ci_jobs (runner_id, state);
CREATE UNIQUE INDEX ci_jobs_active_dedupe ON ci_jobs (repo_id, commit_sha, job_name) WHERE state IN ('queued', 'claimed', 'running');

CREATE TABLE ci_job_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    blake3 TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    CHECK (end_offset >= start_offset)
);
CREATE INDEX ci_job_logs_job_offset ON ci_job_logs (job_id, start_offset);

CREATE TABLE ci_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    blake3 TEXT NOT NULL DEFAULT '',
    sha256 TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX ci_artifacts_job ON ci_artifacts (job_id);

CREATE TABLE ci_job_sessions (
    job_id INTEGER NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    session_ulid TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (job_id, session_ulid)
);

CREATE TABLE ci_job_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    token_hint TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE UNIQUE INDEX ci_job_tokens_hash ON ci_job_tokens (token_hash);
CREATE INDEX ci_job_tokens_job ON ci_job_tokens (job_id);

ALTER TABLE sessions ADD COLUMN ci_job_id INTEGER REFERENCES ci_jobs (id) ON DELETE SET NULL;
CREATE INDEX sessions_ci_job ON sessions (ci_job_id);
