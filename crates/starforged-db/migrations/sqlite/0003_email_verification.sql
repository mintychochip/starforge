-- Starforge M0.5: verified email addresses and one-time emailed links (forge-basics design §4.2-§4.3).
-- Keep in lockstep with ../postgres/0003_email_verification.sql.

ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
-- Accounts created before this migration were made by an administrator, who vouches for their addresses.
UPDATE users SET email_verified = 1 WHERE email IS NOT NULL;

CREATE TABLE email_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'change_email', 'reset_password')),
    token_hash TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX email_tokens_user ON email_tokens (user_id, purpose);
