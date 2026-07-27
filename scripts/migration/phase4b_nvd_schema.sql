-- Phase 4B: additive schema expansion for historical NVD fidelity.

ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v31_score DOUBLE PRECISION;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v31_vector TEXT;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v31_severity TEXT;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v30_score DOUBLE PRECISION;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v30_vector TEXT;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v30_severity TEXT;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v2_score DOUBLE PRECISION;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v2_vector TEXT;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cvss_v2_severity TEXT;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS nvd_references JSONB;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS cpe_configurations JSONB;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS weaknesses JSONB;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS vendor_comments JSONB;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS source_identifier TEXT;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS vuln_status TEXT;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS last_modified_date TIMESTAMPTZ;
ALTER TABLE nvd_intel
  ADD COLUMN IF NOT EXISTS epss_percentile DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_nvd_intel_last_modified_date ON nvd_intel (last_modified_date DESC);
CREATE INDEX IF NOT EXISTS idx_nvd_intel_source_identifier ON nvd_intel (source_identifier);
CREATE INDEX IF NOT EXISTS idx_nvd_intel_vuln_status ON nvd_intel (vuln_status);

CREATE TABLE IF NOT EXISTS nvd_backfill_checkpoint (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  window_start TIMESTAMPTZ NOT NULL,
  window_end TIMESTAMPTZ NOT NULL,
  start_index INTEGER NOT NULL DEFAULT 0,
  processed_cves BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS nvd_backfill_runs (
  id BIGSERIAL PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  status TEXT NOT NULL,
  note TEXT,
  processed_cves BIGINT NOT NULL DEFAULT 0
);
