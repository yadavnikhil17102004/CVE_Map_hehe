# CVE-Intel

CVE-Intel is a vulnerability intelligence platform that correlates three streams:

- GitHub CVE-tagged PoC repositories
- NVD/CVSS/CWE/KEV/EPSS enrichment
- Cybersecurity news feeds

It is now productionized on a VPS stack (Postgres + FastAPI + Caddy) and served at:

- Site: `https://cve-intel.duckdns.org`
- API docs: `https://cve-intel.duckdns.org/docs`
- OpenAPI JSON: `https://cve-intel.duckdns.org/openapi.json`

## What This Project Does

At a high level, CVE-Intel continuously ingests public CVE-related data, normalizes it, stores it in Postgres, and exposes it through a public API + frontend.

The system is designed for:

- security researchers
- defenders and blue teams
- integrators who want API access to CVE-repo-news context

## Internal Working (End-to-End)

### 1) GitHub PoC mapping (`cvemapping.go`)

- Runs on schedule (6h cycle as part of scrape job).
- Searches GitHub repositories for CVE patterns (year-scoped, monthly partitioned queries to work around GitHub Search result limits).
- Normalizes repository records into CVE-linked rows.
- Writes to Postgres table: `cve_repos`.

### 2) NVD enrichment (`nvd_scraper.go`)

- Runs in same 6h scrape job after CVE mapping.
- Phase 1: pulls new/modified CVEs from NVD API in time windows.
- Phase 2: targeted backfill for missing/unscored CVEs from `cve_repos` linkage.
- Phase 3: EPSS enrichment (bulk/optimized loading path).
- Performs batched upserts into `nvd_intel` with retry/timeout controls.

### 3) News ingestion (`news_scraper.go`)

- Runs every hour.
- Pulls configured RSS/news sources, normalizes/deduplicates.
- Writes into `news_items`.

### 4) Validation gate (`validate.go`)

- Runs at end of scrape cycle.
- Checks table-level sanity and enrichment coverage.
- Scrape service only completes when validation passes.

### 5) API serving (`api/main.py`)

- FastAPI reads Postgres via read-only credentials.
- Exposes frontend-compatible and integration-friendly endpoints.
- Supports compression, pagination/filtering, and rate limiting.

### 6) Frontend

- Static pages (`index.html`, `dashboard.html`, `news.html`, `docs.html`) served by Caddy.
- Frontend calls `/api/*` instead of reading local JSON files.

## Architecture

```text
GitHub Search + NVD + EPSS + RSS feeds
                 |
             Go ingestion jobs
                 |
          Postgres (source of truth)
                 |
         FastAPI read API layer
                 |
     Caddy (TLS + reverse proxy)
                 |
      https://cve-intel.duckdns.org
```

## API Surface

- `GET /api/cve/{year}`
- `GET /api/intel/{year}`
- `GET /api/intel-summary/{year}` (intel only for CVEs that have mapped repos in that year)
- `GET /api/news`
- `GET /api/search?q=...&page=...&per_page=...`
- `GET /api/health`

Pagination:
- `/api/cve/{year}` supports optional `page` + `per_page` (defaults to full year if omitted).
- `/api/intel/{year}` supports optional `page` + `per_page` and optional `cve_ids` (comma-separated).

## Data Distribution Model

Two-tier model:

1. Primary: live API (`/api/*`) from Postgres
2. Secondary: weekly bulk snapshot via GitHub Releases assets

Bulk datasets are intentionally not committed into branch history.

## Repository Layout

- `cvemapping.go`: GitHub CVE repo mapper
- `nvd_scraper.go`: NVD/KEV/EPSS enrichment engine
- `news_scraper.go`: hourly news ingestion
- `validate.go`: DB validation gate
- `api/`: FastAPI service
- `scripts/migration/`: migration and verification scripts
- `scripts/ops/`: ops health checks, Telegram bot units/scripts
- `MIGRATION_LOG.md`: migration execution record
- `STATUS.md`: current operational snapshot
- `ROADMAP.md`: planned future intelligence work

## Operations and Scheduling

VPS uses systemd timers:

- `cveintel-scrape.timer`: every 6 hours
- `cveintel-news.timer`: every 1 hour
- `cveintel-backup.timer`: daily backup job
- `cveintel-public-snapshot.timer`: weekly public snapshot release job
- `cveintel-ops-health.timer`: ops freshness/health monitor

Auxiliary:

- `cveintel-duckdns.timer`: keeps DuckDNS record updated
- `cveintel-telegram-bot.service`: read-only Telegram command bot

## Backups and Recovery

- Daily Postgres dump is generated and synced to private backup repository.
- Large dumps are handled via Git LFS in backup repo.
- Restore validity has been verified during migration (`pg_restore --list` checks).

## Monitoring and Alerting

- Ops health script writes `/var/log/cveintel/ops_health_status.json`.
- Alerts are sent to Telegram with readable per-service status.
- Supported Telegram commands:
  - `/status`
  - `/scrape`
  - `/backup`
  - `/help`

## Development and CI

- CI workflow remains in `.github/workflows/ci.yml`.
- Legacy scheduled GitHub workflows were removed after VPS migration.

## Legacy Snapshot

Pre-VPS static-era baseline is preserved at git tag:

- `legacy-static-v1`

## Ethical and Safety Notice

This project indexes third-party exploit/PoC references for defensive research and prioritization.

- External links may be unsafe or inaccurate.
- Inclusion is not endorsement.
- Use isolated sandboxes/lab environments for exploit analysis.
- Do not use this project for unauthorized or illegal activity.

## Documentation Index

- [MIGRATION_LOG.md](MIGRATION_LOG.md)
- [STATUS.md](STATUS.md)
- [ROADMAP.md](ROADMAP.md)
- [vps-migration-instructions.md](vps-migration-instructions.md)
