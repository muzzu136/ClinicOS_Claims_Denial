-- 0007_eligibility_checks.sql
--
-- Append-only: do not edit after this file has been deployed.
-- See worker/migrations/0001_initial.sql for the full rules.

CREATE TABLE eligibility_checks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  member_id_last4 TEXT NOT NULL,
  payer TEXT NOT NULL,
  cpt_code TEXT,
  result_status TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX idx_eligibility_checks_user_id ON eligibility_checks(user_id);
CREATE INDEX idx_eligibility_checks_user_created ON eligibility_checks(user_id, created_at DESC);
