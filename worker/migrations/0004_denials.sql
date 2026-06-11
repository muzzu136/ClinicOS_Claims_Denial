-- 0004_denials.sql
--
-- Append-only: do not edit after this file has been deployed.

CREATE TABLE denials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  payer TEXT NOT NULL,
  cpt_code TEXT NOT NULL,
  denial_reason_code TEXT NOT NULL,
  denial_reason_label TEXT NOT NULL,
  date_of_service TEXT NOT NULL,
  claim_amount REAL NOT NULL,
  notes TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX idx_denials_user_id ON denials(user_id);
CREATE INDEX idx_denials_user_created ON denials(user_id, created_at DESC);
