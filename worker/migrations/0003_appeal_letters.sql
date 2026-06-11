-- 0003_appeal_letters.sql
--
-- Append-only: do not edit after this file has been deployed.

CREATE TABLE appeal_letters (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  denial_code TEXT NOT NULL,
  denial_label TEXT NOT NULL,
  patient_id TEXT NOT NULL,
  date_of_service TEXT NOT NULL,
  cpt_code TEXT NOT NULL,
  payer_name TEXT NOT NULL,
  billed_amount REAL NOT NULL,
  npi TEXT NOT NULL,
  notes TEXT,
  letter_text TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX idx_appeal_letters_user_id ON appeal_letters(user_id);
-- See worker/migrations/0001_initial.sql for the full rules.

