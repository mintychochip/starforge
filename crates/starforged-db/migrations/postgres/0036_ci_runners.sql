-- Starforge M6-0: opt-in self-hosted CI runners (control plane only).
-- Keep in lockstep with ../sqlite/0036_ci_runners.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
--
-- Token columns store SHA-256 hashes only; plaintext tokens are shown once
-- at mint/registration time and never stored. `labels` and ci_jobs `spec`
-- are TEXT holding JSON (no JSON operators — both engines). `ci_jobs` is a
-- separate queue from the internal `jobs` table: it carries a per-claim
-- `lease_token` fence (decision 13). `git_token_id` links the short-lived
-- git credential minted for the job (access_tokens) so finish/cancel can
-- revoke it. `ci_jobs` is created before the `sessions` ALTER below.

CREATE TABLE runners (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL,
    token_hint TEXT NOT NULL DEFAULT '',
    labels TEXT NOT NULL DEFAULT '[]',
    ephemeral BIGINT NOT NULL DEFAULT 0,
    paused BIGINT NOT NULL DEFAULT 0,
    max_concurrent BIGINT NOT NULL DEFAULT 1 CHECK (max_concurrent >= 1),
    version TEXT NOT NULL DEFAULT '',
    last_seen_at BIGINT,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT
);
CREATE INDEX runners_repo ON runners (repo_id);
CREATE INDEX runners_token_hash ON runners (token_hash);

CREATE TABLE runner_registration_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    labels TEXT NOT NULL DEFAULT '[]',
    created_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    created_at BIGINT NOT NULL
);
CREATE INDEX runner_registration_tokens_hash ON runner_registration_tokens (token_hash);
CREATE INDEX runner_registration_tokens_repo ON runner_registration_tokens (repo_id);

CREATE TABLE ci_jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    trail_id BIGINT REFERENCES trails (id) ON DELETE CASCADE,
    change_id BIGINT REFERENCES changes (id) ON DELETE CASCADE,
    revision_id BIGINT REFERENCES revisions (id) ON DELETE CASCADE,
    commit_sha TEXT NOT NULL,
    base_sha TEXT,
    job_name TEXT NOT NULL,
    spec TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'claimed', 'running', 'succeeded', 'failed', 'canceled')),
    runner_id BIGINT REFERENCES runners (id) ON DELETE SET NULL,
    attempts BIGINT NOT NULL DEFAULT 0,
    run_at BIGINT NOT NULL,
    lease_until BIGINT,
    lease_token TEXT,
    deadline BIGINT NOT NULL,
    exit_code BIGINT,
    checksum TEXT,
    cancel_requested BIGINT NOT NULL DEFAULT 0,
    created_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    git_token_id BIGINT REFERENCES access_tokens (id) ON DELETE SET NULL,
    last_error TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    started_at BIGINT,
    finished_at BIGINT
);
CREATE INDEX ci_jobs_state_run_at ON ci_jobs (state, run_at);
CREATE INDEX ci_jobs_repo_commit ON ci_jobs (repo_id, commit_sha);
CREATE INDEX ci_jobs_runner_state ON ci_jobs (runner_id, state);
CREATE UNIQUE INDEX ci_jobs_active_dedupe ON ci_jobs (repo_id, commit_sha, job_name) WHERE state IN ('queued', 'claimed', 'running');

CREATE TABLE ci_job_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    start_offset BIGINT NOT NULL,
    end_offset BIGINT NOT NULL,
    blake3 TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    CHECK (end_offset >= start_offset)
);
CREATE INDEX ci_job_logs_job_offset ON ci_job_logs (job_id, start_offset);

CREATE TABLE ci_artifacts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    blake3 TEXT NOT NULL DEFAULT '',
    sha256 TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX ci_artifacts_job ON ci_artifacts (job_id);

CREATE TABLE ci_job_sessions (
    job_id BIGINT NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    session_ulid TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (job_id, session_ulid)
);

CREATE TABLE ci_job_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    token_hint TEXT NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT
);
CREATE INDEX ci_job_tokens_hash ON ci_job_tokens (token_hash);
CREATE INDEX ci_job_tokens_job ON ci_job_tokens (job_id);

ALTER TABLE sessions ADD COLUMN ci_job_id BIGINT REFERENCES ci_jobs (id) ON DELETE SET NULL;
CREATE INDEX sessions_ci_job ON sessions (ci_job_id);
