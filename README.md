# CVE-Intel

CVE-Intel is a live vulnerability intelligence platform that correlates:

- GitHub PoC/exploit repositories
- NVD CVSS/CWE/KEV/EPSS intelligence
- cybersecurity news feeds

The production stack now runs on a VPS with Postgres + FastAPI, and serves a static frontend over Caddy/HTTPS.

## Live endpoints

- Public site: `https://cve-intel.duckdns.org`
- API docs (OpenAPI): `https://cve-intel.duckdns.org/docs`
- OpenAPI JSON: `https://cve-intel.duckdns.org/openapi.json`

## Data access model

CVE-Intel uses a two-tier access model:

1. **Primary (live integration path):** FastAPI endpoints backed by Postgres (`/api/*`)
2. **Secondary (bulk/offline path):** weekly snapshot artifacts published via GitHub Releases

Snapshots are published as release assets and are **not** committed to branch history.

## Legacy static-era snapshot

The old static GitHub-Pages-style baseline is preserved as git tag:

- `legacy-static-v1`

That tag is a permanent rollback/reference point for the pre-VPS architecture.

## Current architecture

```text
GitHub Search + NVD + FIRST EPSS + RSS feeds
                   |
                Go scrapers
                   |
             (Postgres-only writes)
                   |
             Postgres (source of truth)
                   |
               FastAPI (/api/*)
                   |
        Caddy reverse proxy + static UI
                   |
         https://cve-intel.duckdns.org
```

## API surface

- `GET /api/cve/{year}`
- `GET /api/intel/{year}`
- `GET /api/news`
- `GET /api/search?q=...&page=...&per_page=...`
- `GET /api/health`

Notes:

- `/api/search` supports server-side pagination/filtering.
- API uses response compression and request rate limiting.
- API runs with a dedicated **read-only** Postgres role.

## Repository structure (high-level)

- `cvemapping.go` - GitHub PoC mapping scraper
- `nvd_scraper.go` - NVD/KEV/EPSS enrichment scraper
- `news_scraper.go` - multi-source cyber news ingestion
- `api/` - FastAPI service
- `scripts/migration/` - migration/backfill/verification utilities
- `MIGRATION_LOG.md` - durable migration execution record
- `ROADMAP.md` - planned trust/news intelligence work

## CI and automation

GitHub Actions is CI-focused:

- `.github/workflows/ci.yml`

Legacy scheduled workflow files were removed from `main` after VPS migration.

## Operational status

- Production hostname: `cve-intel.duckdns.org` (HTTPS via Caddy + Let's Encrypt)
- Scrape/news jobs: systemd timers on VPS (`6h` scrape, `1h` news)
- Backups: daily Postgres dump to private backup repo (LFS-backed for large dump)
- Public distribution: weekly snapshot release assets on GitHub Releases
- Alerting: Telegram ops alerts + read-only bot commands (`/status`, `/scrape`, `/backup`, `/help`)

For date-stamped evidence (row counts, timer runs, incident fixes), see `MIGRATION_LOG.md`.

## Ethical use and safety notice

This project indexes third-party exploit/PoC references for research and defensive prioritization.

- Links and repositories are externally sourced and may be inaccurate, incomplete, or unsafe.
- Inclusion does **not** imply endorsement, validation, or safety.
- Use isolated analysis environments and proper malware-handling practices.
- Do not use this project for unauthorized access or illegal activity.

## Documentation

- Migration execution log: [MIGRATION_LOG.md](MIGRATION_LOG.md)
- Forward plan (trust scoring + news intelligence): [ROADMAP.md](ROADMAP.md)
- Historical migration plan: [vps-migration-instructions.md](vps-migration-instructions.md)
