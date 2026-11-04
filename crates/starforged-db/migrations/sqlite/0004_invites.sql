-- Starforge M0.5: single-use sign-up invites (forge-basics design §4.1).
-- Keep in lockstep with ../postgres/0004_invites.sql.

CREATE TABLE invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash TEXT NOT NULL UNIQUE,
    email TEXT,
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    used_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    revoked_at INTEGER
);
