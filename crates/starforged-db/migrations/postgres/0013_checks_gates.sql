-- Starforge M2c: commit checks, gate rules, webhooks, and webhook deliveries.
-- Keep in lockstep with ../sqlite/0013_checks_gates.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
--
-- `checks` holds one current row per (repo, sha, context): `insert_check`
-- upserts on the UNIQUE constraint and bumps `updated_at`, so
-- `latest_checks_for_sha` is a plain filtered select. `gate_rules`
-- `required_contexts` / `allowed_methods` are TEXT holding JSON arrays (no
-- JSON operators — both engines); NULL/empty pattern matches all branches.
-- `webhooks.secret_encrypted` is TEXT holding `v1:<base64(nonce‖ciphertext)>`
-- AEAD ciphertext; the db layer stores what it is given and never encrypts.
-- User FKs (`checks.creator_id`) are nullable ON DELETE SET NULL so history
-- survives account deletion; rows inside one aggregate cascade.

CREATE TABLE checks (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    sha TEXT NOT NULL,
    context TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'success', 'failure', 'error')),
    target_url TEXT,
    description TEXT,
    creator_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (repo_id, sha, context)
);
CREATE INDEX checks_repo_sha ON checks (repo_id, sha);

CREATE TABLE gate_rules (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    pattern TEXT,
    required_approvals BIGINT NOT NULL DEFAULT 0 CHECK (required_approvals >= 0),
    dismiss_on_push BIGINT NOT NULL DEFAULT 0,
    block_on_request_changes BIGINT NOT NULL DEFAULT 1,
    required_contexts TEXT NOT NULL DEFAULT '[]',
    require_up_to_date BIGINT NOT NULL DEFAULT 0,
    require_threads_resolved BIGINT NOT NULL DEFAULT 0,
    require_session_evidence BIGINT NOT NULL DEFAULT 0,
    allowed_methods TEXT NOT NULL DEFAULT '[]',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX gate_rules_repo ON gate_rules (repo_id);

CREATE TABLE webhooks (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret_encrypted TEXT NOT NULL DEFAULT '',
    events TEXT NOT NULL DEFAULT '[]',
    active BIGINT NOT NULL DEFAULT 1,
    last_status BIGINT,
    last_error TEXT,
    created_at BIGINT NOT NULL
);
CREATE INDEX webhooks_repo ON webhooks (repo_id);

CREATE TABLE webhook_deliveries (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    webhook_id BIGINT NOT NULL REFERENCES webhooks (id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '',
    status_code BIGINT,
    error TEXT,
    delivered_at BIGINT NOT NULL
);
CREATE INDEX webhook_deliveries_hook ON webhook_deliveries (webhook_id);
