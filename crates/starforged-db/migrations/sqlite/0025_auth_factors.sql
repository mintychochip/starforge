-- Starforge M3d: TOTP two-factor, recovery codes, OIDC identities, login challenges (spec §9).
-- Keep in lockstep with ../postgres/0025_auth_factors.sql.
--
-- `users.totp_secret` holds the AEAD-sealed TOTP secret (`v1:<base64(nonce‖ciphertext)>`,
-- the webhook seal shape) and stays NULL until enrollment begins; `totp_enabled` flips
-- to 1 only after a valid enrollment code is confirmed. `totp_last_step` is the highest
-- TOTP step already accepted, so a replayed or older code is refused.
-- `recovery_codes` stores SHA-256 hashes of the normalized codes only.
-- `user_identities` links a user to an OIDC (issuer, subject); one identity belongs to
-- one user. `login_challenges` carries the server-side state of a login in progress:
-- a TOTP challenge (kind `totp`) or an OIDC authorization-code flow (kind `oidc`, with
-- the `state`, `nonce`, and PKCE verifier fields the later OIDC tasks use). The
-- browser holds only the random token; its SHA-256 is stored here.

ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1));
ALTER TABLE users ADD COLUMN totp_last_step INTEGER;

CREATE TABLE recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

CREATE TABLE user_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (issuer, subject)
);
CREATE INDEX user_identities_user ON user_identities (user_id);

CREATE TABLE login_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('totp', 'oidc')),
    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    state TEXT,
    nonce TEXT,
    code_verifier TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX login_challenges_user ON login_challenges (user_id);
