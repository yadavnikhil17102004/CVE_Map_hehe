# CVE-Intel Operations Runbook

Last updated: 2026-07-28

This runbook is the operator-facing guide for deploys, service control, and production verification on the VPS environment.

## Scope

- Hostname: `https://cve-intel.duckdns.org`
- API/docs: `/api/*`, `/docs`, `/openapi.json`
- Stack: Caddy + FastAPI + Postgres + systemd timers/services

## 1) Service Discovery (API/Web Process)

Use these commands first when the API service unit name is unknown.

```bash
systemctl list-units --type=service | grep -i cveintel
```

If no obvious API unit appears, identify the process Caddy proxies to:

```bash
ss -tlnp | grep 8000
```

Then map PID -> service:

```bash
ps -fp <PID>
```

## 2) Core Scheduler Units

- `cveintel-scrape.timer` / `cveintel-scrape.service` (6h ingest cycle)
- `cveintel-news.timer` / `cveintel-news.service` (hourly news)
- `cveintel-backup.timer` / `cveintel-backup.service` (daily DB backup)
- `cveintel-public-snapshot.timer` / `cveintel-public-snapshot.service` (weekly snapshot)
- `cveintel-ops-health.timer` / `cveintel-ops-health.service` (ops monitoring)
- `cveintel-duckdns.timer` / `cveintel-duckdns.service` (dynamic DNS updater)
- `cveintel-telegram-bot.service` (read-only bot)

Check timer states:

```bash
systemctl list-timers --all | grep cveintel
```

## 3) Standard Service Checks

Replace `<api-service-name>` after discovery.

```bash
sudo systemctl status <api-service-name> --no-pager
sudo journalctl -u <api-service-name> --since "-15 minutes" --no-pager
```

Batch services:

```bash
sudo systemctl status cveintel-scrape.service cveintel-news.service --no-pager
sudo journalctl -u cveintel-scrape.service --since "-30 minutes" --no-pager
```

## 4) Deploy Runbook (Main Branch)

On VPS:

```bash
cd /path/to/CVE-Intel
git fetch origin
git log origin/main -1 --oneline
git pull origin main
```

Restart API process:

```bash
sudo systemctl restart <api-service-name>
sudo systemctl status <api-service-name> --no-pager
sudo journalctl -u <api-service-name> --since "-5 minutes" --no-pager
```

## 5) Post-Deploy API Verification

Health and route checks:

```bash
curl -sS https://cve-intel.duckdns.org/api/health
curl -sI https://cve-intel.duckdns.org/api/intel-summary/2026
curl -sI "https://cve-intel.duckdns.org/api/cve/2026?page=1&per_page=50"
curl -sI "https://cve-intel.duckdns.org/api/search?q=openssl&page=1&per_page=10"
```

Header/payload checks:

```bash
curl -sI https://cve-intel.duckdns.org/api/intel/2026 | grep -i -E "content-length|cache-control"
curl -sI https://cve-intel.duckdns.org/api/intel-summary/2026 | grep -i -E "content-length|cache-control"
```

Expected outcomes for latest API revision:

- `/api/intel-summary/2026` returns `200` (not `404`)
- cache headers are present on API responses as configured by backend route policy
- summary endpoint payload is materially smaller than full-year `/api/intel/2026`

## 6) Rollback (If API restart fails)

```bash
cd /path/to/CVE-Intel
git log --oneline -n 5
git checkout <last-known-good-commit>
sudo systemctl restart <api-service-name>
sudo systemctl status <api-service-name> --no-pager
```

After stabilization, restore branch state:

```bash
git checkout main
```

## 7) Evidence Logging

For any production-impacting deploy/update, append:

- commit deployed
- service restart result
- journal error/success summary
- endpoint verification output

Record in:

- `MIGRATION_LOG.md` (detailed event evidence)
- `STATUS.md` (high-level current posture)
