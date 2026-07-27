-- Phase 5 archival follow-up: non-destructive repo presence tracking.
-- Tracks when a CVE/repo tuple was last observed in a successful cvemapping run.

ALTER TABLE cve_repos
ADD COLUMN IF NOT EXISTS last_seen_in_scrape_at timestamptz;

-- One-time backfill for existing rows so older data has a usable baseline.
UPDATE cve_repos
SET last_seen_in_scrape_at = COALESCE(last_seen_in_scrape_at, discovered_at, NOW())
WHERE last_seen_in_scrape_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_cve_repos_last_seen_in_scrape_at
ON cve_repos (last_seen_in_scrape_at DESC);
