-- Starforge M0 schema for Postgres. Keep in lockstep with ../sqlite/0001_initial.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

CREATE TABLE owners (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('user', 'org')),
    handle TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL
);

CREATE TABLE users (
    id BIGINT PRIMARY KEY REFERENCES owners (id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT UNIQUE,
    password_hash TEXT,
    is_admin BIGINT NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended')),
    created_at BIGINT NOT NULL
);

CREATE TABLE access_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_hint TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_used_at BIGINT,
    revoked_at BIGINT
);
CREATE INDEX access_tokens_user ON access_tokens (user_id);

CREATE TABLE web_sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX web_sessions_user ON web_sessions (user_id);

CREATE TABLE repos (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES owners (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    lower_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'internal', 'private')),
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (owner_id, lower_name)
);

CREATE TABLE collaborators (
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'triage', 'write', 'maintain', 'admin')),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (repo_id, user_id)
);
CREATE INDEX collaborators_user ON collaborators (user_id);

CREATE TABLE audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);
CREATE INDEX audit_log_created ON audit_log (created_at);
