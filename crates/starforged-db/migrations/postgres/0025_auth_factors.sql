-- Starforge M3d: TOTP two-factor, recovery codes, OIDC identities, login challenges (spec §9).
-- Keep in lockstep with ../sqlite/0025_auth_factors.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
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
ALTER TABLE users ADD COLUMN totp_enabled BIGINT NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1));
ALTER TABLE users ADD COLUMN totp_last_step BIGINT;

CREATE TABLE recovery_codes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    used_at BIGINT
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

CREATE TABLE user_identities (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (issuer, subject)
);
CREATE INDEX user_identities_user ON user_identities (user_id);

CREATE TABLE login_challenges (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('totp', 'oidc')),
    user_id BIGINT REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    state TEXT,
    nonce TEXT,
    code_verifier TEXT,
    attempts BIGINT NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX login_challenges_user ON login_challenges (user_id);
