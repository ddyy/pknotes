-- Recovery codes become single-use. redeemed_at records the first successful
-- redemption; the Worker allows re-redemption only within a short grace window
-- (so an interrupted recovery can retry) and rejects the code afterwards.
-- A successful recovery replaces the row with a freshly generated code.
ALTER TABLE recovery ADD COLUMN redeemed_at INTEGER;
