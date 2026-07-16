-- Master-key rotation is now staged: the client uploads re-encrypted note
-- ciphertext into pending_ciphertext in chunks (so no single D1 batch exceeds
-- the per-invocation query limit), then a final atomic commit swaps every
-- pending value into ciphertext in one bulk statement. Nothing is readable
-- under a half-applied key: the old ciphertext stays live until commit.
ALTER TABLE notes ADD COLUMN pending_ciphertext TEXT;

-- Sessions are stateless HMAC cookies, so deleting a credential can't revoke a
-- device that's already signed in. session_epoch is embedded in each session
-- token; rotation increments it, invalidating every other device immediately.
ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
