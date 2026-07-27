# CVE-Intel Status

Last updated: 2026-07-27

## Production Runtime

- Hostname: `https://cve-intel.duckdns.org`
- API docs: `/docs`
- Source of truth: Postgres
- Frontend: static pages served via Caddy

## Scheduler/Jobs

- Scrape cycle: every 6h (`cveintel-scrape.timer`)
- News cycle: every 1h (`cveintel-news.timer`)
- Backup cycle: daily (`cveintel-backup.timer`)
- Public snapshot: weekly (`cveintel-public-snapshot.timer`)
- Ops health check: every 15 min (`cveintel-ops-health.timer`)

## Ops/Alerting

- Telegram alerts: enabled
- Telegram bot: enabled (read-only commands)
- DuckDNS updater: enabled

## Data Distribution

- Live integration path: FastAPI (`/api/*`)
- Bulk/offline path: weekly GitHub Release assets

## Current Phase Posture

Migration is in post-cutover operations mode.

- JSON-removal gate treated as closed after successful timer-driven scrape completion with validation pass.
- Remaining work is roadmap-level enhancement (trust/risk scoring and advanced news intelligence), tracked in `ROADMAP.md`.

## Where To Look

- Detailed migration evidence: `MIGRATION_LOG.md`
- Future feature plan: `ROADMAP.md`
- Historical migration plan: `vps-migration-instructions.md`
