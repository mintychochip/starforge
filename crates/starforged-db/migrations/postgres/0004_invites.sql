-- Starforge M0.5: single-use sign-up invites (forge-basics design §4.1).
-- Keep in lockstep with ../sqlite/0004_invites.sql.

CREATE TABLE invites (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    email TEXT,
    created_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    used_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    revoked_at BIGINT
);
