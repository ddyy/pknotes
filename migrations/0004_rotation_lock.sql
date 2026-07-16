-- Concurrency control for master-key rotation.
--
-- active_rotation is a per-user lock: while set (and not expired), note
-- writes and other rotations are refused, so the check-then-commit window
-- can't be raced. rotation_started drives lock expiry (an abandoned rotation
-- can't wedge the account forever).
ALTER TABLE users ADD COLUMN active_rotation TEXT;
ALTER TABLE users ADD COLUMN rotation_started INTEGER;

-- pending_rotation tags which rotation staged a note's pending_ciphertext, so
-- two concurrent rotations can never commit one rotation's ciphertext under
-- another's wrapped key.
ALTER TABLE notes ADD COLUMN pending_rotation TEXT;
