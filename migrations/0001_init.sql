-- pknotes initial schema. The server only ever stores ciphertext and
-- wrapped (encrypted) keys — nothing in this database is readable without
-- a user's passkey or recovery code.

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE credentials (
  id TEXT PRIMARY KEY, -- WebAuthn credential id (base64url)
  user_id TEXT NOT NULL REFERENCES users(id),
  public_key TEXT NOT NULL, -- COSE public key (base64url)
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT, -- JSON array
  wrapped_mk TEXT NOT NULL, -- master key wrapped by this passkey's PRF-derived KEK (base64url iv||ct)
  prf_salt TEXT NOT NULL, -- PRF eval salt used with this credential (base64url)
  created_at INTEGER NOT NULL
);

CREATE INDEX credentials_user ON credentials(user_id);

CREATE TABLE recovery (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  verifier_hash TEXT NOT NULL, -- SHA-256 of the recovery verifier (base64url)
  wrapped_mk TEXT NOT NULL, -- master key wrapped by the recovery-code-derived KEK
  created_at INTEGER NOT NULL
);

CREATE TABLE notes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  ciphertext TEXT NOT NULL, -- base64url(iv||ct) of the note's markdown
  version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX notes_user ON notes(user_id, updated_at DESC);
