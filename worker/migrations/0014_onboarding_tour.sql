-- 0014_onboarding_tour.sql
-- Add onboarding tour dismissal flag to users

ALTER TABLE users ADD COLUMN onboarding_tour_dismissed INTEGER NOT NULL DEFAULT 0;
