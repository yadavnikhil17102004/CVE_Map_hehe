# CVE-Intel Status

Last updated: 2026-07-29

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
- Ops-health successful-run notifications: recovery-only by default (`OPS_HEALTH_NOTIFY_OK_EVERY_RUN=false`)
- Scrape resilience hardening artifact tracked in repo: `deploy/systemd/cveintel-scrape.service.d/override.conf`

## Data Distribution

- Live integration path: FastAPI (`/api/*`)
- Bulk/offline path: weekly GitHub Release assets

## Current Phase Posture

Migration is in post-cutover operations mode.

- JSON-removal gate treated as closed after successful timer-driven scrape completion with validation pass.
- Remaining work is roadmap-level enhancement (trust/risk scoring and advanced news intelligence), tracked in `ROADMAP.md`.

## Recent Main-Branch Changes (2026-07-28)

- Published API and dashboard performance commits to `origin/main`:
  - `d1c785af` (`api/main.py`, `README.md`, `docs.html`, `index.html`, `LICENSE`)
  - `96934091` (`dashboard.html`)
- New API behavior on `main` includes:
  - optional pagination for `/api/cve/{year}` and `/api/intel/{year}`
  - optional `cve_ids` scoping on `/api/intel/{year}`
  - new `/api/intel-summary/{year}` route
  - route-specific cache headers

## Deployment Note

- Repository is updated on GitHub `main`.
- API deployment to VPS is completed (2026-07-28) using clean worktree build context.
- Live host now serves:
  - `/api/intel-summary/{year}` -> `200`
  - `Cache-Control` headers on intel routes (`public, max-age=300`)
  - gzip compression for clients requesting it (`Content-Encoding: gzip`)
- Observed payload size (2026 sample check):
  - `/api/intel-summary/2026`: ~1.0 MB
  - `/api/intel/2026`: ~25.5 MB
  - gzip requested summary payload: ~283 KB

## UI Note (2026-07-28)

- Dashboard UX prioritization pass completed in `dashboard.html`:
  - quick-filter chips for urgent presets (`Actively Exploited`, `Critical + KEV`, `Critical Only`, `High EPSS`)
  - severity/KEV-first row badges and two-tier row density
  - skeleton loaders for CVE list and activity feed
  - explicit zero-match state with `Clear Filters` action.

## CI Note (2026-07-28)

- GitHub Actions `CI` failure on docs push was caused by DB validation running without DB credentials in GitHub-hosted CI.
- Workflow now gates `go run validate.go` behind `secrets.DATABASE_URL` and skips cleanly when absent.
- Node.js 20 deprecation message in annotations is advisory and not the failure cause.
- Workflow action versions were upgraded (`checkout/setup-go/setup-python`) to remove Node 20 deprecation warning noise in subsequent runs.
- Browser smoke tests now run against `scripts/ci/mock_api_server.py` so API-dependent frontend checks execute with deterministic local `/api/*` responses in CI.
- Latest CI verification:
  - Run `30345385404` (commit `b0ac54ef`) completed successfully, including `Run browser smoke tests`.

## Where To Look

- Detailed migration evidence: `MIGRATION_LOG.md`
- Future feature plan: `ROADMAP.md`
- Historical migration plan: `vps-migration-instructions.md`
- Deploy/operations runbook: `OPERATIONS.md`
