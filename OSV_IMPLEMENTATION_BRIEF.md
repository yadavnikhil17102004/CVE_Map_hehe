# OSV Integration Implementation Brief (CVE-Intel)

## Objective
Add OSV.dev data as a first-class enrichment source for CVE-Intel, with a CVE-first read path but OSV-native ingestion model.

## Critical Design Constraint (Do Not Skip)
OSV is not primarily keyed by CVE IDs. OSV-native IDs (`GHSA-*`, `PYSEC-*`, etc.) are canonical, while CVE appears as one alias among many.

Implication:
- Do not design ingestion around `CVE -> OSV lookup` as the primary fetch pattern.
- Ingest OSV records by OSV identity, then resolve CVE relationships via aliases.
- Dedup/matching across aliases is our responsibility.

## Pre-Coding Verification Gate (Required)
Before implementation, verify field names and export/API structure against current OSV docs/schema (do not assume from memory):
- record identity fields
- alias arrays
- affected package/ecosystem structure
- modified/published timestamps
- references/severity ranges affected events

If verified names differ from this brief, prefer OSV docs and update this brief + migration log before coding.

## Data Model (Phase 1)

### New tables
1. `osv_advisories`
- `osv_id` TEXT PRIMARY KEY
- `summary` TEXT NULL
- `details` TEXT NULL
- `published_at` TIMESTAMPTZ NULL
- `modified_at` TIMESTAMPTZ NULL
- `withdrawn_at` TIMESTAMPTZ NULL
- `raw_json` JSONB NOT NULL
- `ingested_at` TIMESTAMPTZ NOT NULL DEFAULT NOW()
- index: `modified_at DESC`

2. `osv_aliases`
- `osv_id` TEXT NOT NULL REFERENCES `osv_advisories`(`osv_id`) ON DELETE CASCADE
- `alias` TEXT NOT NULL
- `alias_type` TEXT NULL (e.g., CVE/GHSA/other, derived locally)
- PRIMARY KEY (`osv_id`, `alias`)
- index: `alias`

3. `osv_packages`
- `osv_id` TEXT NOT NULL REFERENCES `osv_advisories`(`osv_id`) ON DELETE CASCADE
- `ecosystem` TEXT NOT NULL
- `package_name` TEXT NOT NULL
- `purl` TEXT NULL
- `introduced` TEXT NULL
- `fixed` TEXT NULL
- `last_affected` TEXT NULL
- `limit_version` TEXT NULL
- `database_specific` JSONB NULL
- PRIMARY KEY (`osv_id`, `ecosystem`, `package_name`, `introduced`, `fixed`, `last_affected`, `limit_version`)
- indexes:
  - (`ecosystem`, `package_name`)
  - (`osv_id`)

4. `osv_cve_links`
- `cve_id` TEXT NOT NULL
- `osv_id` TEXT NOT NULL REFERENCES `osv_advisories`(`osv_id`) ON DELETE CASCADE
- PRIMARY KEY (`cve_id`, `osv_id`)
- indexes:
  - (`cve_id`)
  - (`osv_id`)

### Why split tables
- Keeps advisory identity stable (`osv_id`)
- Supports alias churn without rewriting whole advisory rows
- Enables fast `CVE -> ecosystems/packages` lookups for dashboard/API

## Ingestion Strategy

### Source mode
Use OSV bulk/export/API mode that is documented as stable for periodic sync. Prefer incremental by `modified` timestamp when supported; otherwise bounded full sync with checkpointing.

### Upsert rules
- `osv_advisories`: upsert by `osv_id`.
- `osv_aliases`: replace-by-osv-id each refresh (delete + insert) or set-wise upsert.
- `osv_packages`: replace-by-osv-id each refresh to avoid stale ranges.
- `osv_cve_links`: rebuild from aliases where `alias` matches CVE regex.

### Checkpointing
Add `osv_sync_checkpoint` table:
- `id` SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id=1)
- `last_modified_cursor` TEXT/ TIMESTAMPTZ (depending on API/export cursor type)
- `last_success_at` TIMESTAMPTZ
- `status` TEXT
- `error` TEXT

### Failure behavior
- Retry with bounded backoff for transient HTTP/network failures.
- Write partial progress only at advisory boundaries.
- Never drop existing data on failed sync.

## Scheduler / Ops

### New unit/timer
- `cveintel-osv-sync.service`
- `cveintel-osv-sync.timer`

### Cadence
- Every 6 hours (aligned with scrape cycle), offset by +20m from scrape start to avoid peak overlap.

### Observability
- Status file: `/var/log/cveintel/osv_sync_status.json`
- Include:
  - `last_success`
  - `records_processed`
  - `records_upserted`
  - `alias_rows`
  - `package_rows`
  - `duration_seconds`
  - `error` (if any)

### Ops-health integration
Add OSV freshness check to ops-health with threshold of 8h and clear alert text.

## API Additions (Phase 1)

### New endpoint
`GET /api/osv-packages/{year}`

Purpose:
- CVE-first to package/ecosystem surface for dashboard analytics.

Parameters:
- `year` path
- `page` (default 1)
- `per_page` (default 200, max 1000)
- optional filters:
  - `ecosystem`
  - `package`
  - `cve_id`

Response shape:
- `year`, `page`, `per_page`, `total`
- `rows[]`:
  - `cve_id`
  - `osv_id`
  - `ecosystem`
  - `package_name`
  - `introduced`
  - `fixed`
  - `last_affected`

Caching:
- `Cache-Control: public, max-age=300`

### Optional endpoint (if cheap)
`GET /api/osv-summary/{year}`
- Aggregates by ecosystem/package counts for at-a-glance cards.
- Same cache policy: `public, max-age=300`.

## UI Surface (Phase 1, minimal)
Add one dashboard module:
- “Vulnerable Packages by Ecosystem”
- Backed by `/api/osv-summary/{year}` (or paged `/api/osv-packages/{year}` if summary route deferred)
- Show top ecosystems and top packages with linked CVE counts.

No auth/accounts needed.

## Backward Compatibility
- Existing API/UI behavior remains unchanged if OSV sync is empty or disabled.
- New UI module must fail soft (empty-state text, no page break).

## Security / Legal / Compliance
- OSV is public advisory intelligence; no scraping of gated/illegal sources.
- Store source attribution in raw advisory JSON and document provenance in docs.

## Acceptance Criteria
1. New tables created via migration with indexes.
2. OSV sync service populates advisory + alias + package + cve-link tables.
3. Sync is idempotent (rerun does not duplicate rows).
4. Ops-health includes OSV freshness signal.
5. New API endpoint returns paginated rows and cache header.
6. Dashboard shows ecosystem/package view for selected year.
7. MIGRATION_LOG + STATUS + OPERATIONS updated with deployment and verification evidence.

## Parallelization Note
OSV integration can run in parallel with Triage UI implementation work:
- OSV workstream touches backend schema/sync/API.
- Triage UI workstream touches `dashboard.html` and frontend interaction model.
- Keep integration boundary at `/api/osv-*` so both branches can merge cleanly.
