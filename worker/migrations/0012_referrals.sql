-- 0012_referrals.sql
--
-- Append-only: do not edit after this file has been deployed.
-- See worker/migrations/0001_initial.sql for the full rules.

-- Add referral_code and referred_by to users
ALTER TABLE users ADD COLUMN referral_code TEXT;
ALTER TABLE users ADD COLUMN referred_by TEXT;

CREATE UNIQUE INDEX idx_users_referral_code ON users(referral_code);
CREATE INDEX idx_users_referred_by ON users(referred_by);

-- Referral credits table
CREATE TABLE referral_credits (
  id TEXT PRIMARY KEY,
  referrer_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  referred_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  credited_at INTEGER
);
CREATE INDEX idx_referral_credits_referrer ON referral_credits(referrer_user_id);
CREATE INDEX idx_referral_credits_referred ON referral_credits(referred_user_id);
