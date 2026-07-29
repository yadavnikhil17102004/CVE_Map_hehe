# CVE-Intel Operations Runbook

Last updated: 2026-07-29

This runbook is the operator-facing guide for deploys, service control, and production verification on the VPS environment.

## Scope

- Hostname: `https://cve-intel.duckdns.org`
- API/docs: `/api/*`, `/docs`, `/openapi.json`
- Stack: Caddy + Docker Compose (`cveintel-api`, `cveintel-postgres`) + systemd timers/services

## 1) Service Discovery (API/Web Process)

The API process is containerized (Docker Compose), not a standalone systemd service.
Use these commands to discover runtime ownership:

```bash
systemctl list-units --type=service | grep -i cveintel
sudo docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
```

Identify the process Caddy proxies to:

```bash
ss -tlnp | grep 8000
```

Then map PID:

```bash
ps -fp <PID>
# if process is docker-proxy, map via docker:
sudo docker ps --format "table {{.Names}}\t{{.Ports}}" | grep 8000
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

API container checks:

```bash
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep cveintel-api
sudo docker logs --since 15m cveintel-api
```

Batch services:

```bash
sudo systemctl status cveintel-scrape.service cveintel-news.service --no-pager
sudo journalctl -u cveintel-scrape.service --since "-30 minutes" --no-pager
sudo journalctl -u cveintel-news.service --since "-24 hours" --no-pager
sudo journalctl -u cveintel-backup.service --since "-24 hours" --no-pager
sudo journalctl -u cveintel-public-snapshot.service --since "-24 hours" --no-pager
```

Status-file quick checks:

```bash
sudo cat /var/log/cveintel/ops_health_status.json
sudo cat /var/log/cveintel/backup_status.json
sudo cat /var/log/cveintel/public_snapshot_status.json
sudo cat /var/log/cveintel/duckdns_status.json
```

Ops-health heartbeat behavior:

- `/usr/local/bin/cveintel-ops-health.sh` sends:
  - `🔴` alert messages on failing checks (with cooldown + dedupe)
  - `✅` pass messages on successful checks (default: recovery edge only)
- Default successful-run behavior is controlled by:
  - `OPS_HEALTH_NOTIFY_OK_EVERY_RUN=false` (default; notify only on non-OK -> OK)
  - set to `true` to send `✅` on every successful 15-minute run.

## 4) Deploy Runbook (Main Branch)

Current VPS reality:

- `~/CVE-Intel` is an actively modified ingestion workspace and may be dirty.
- Deploy API builds from clean worktree: `~/CVE-Intel-deploy`.
- Compose file lives at: `~/cve-intel-vps/docker-compose.yml`.

On VPS (safe path):

```bash
cd ~/CVE-Intel
git fetch origin
git log origin/main -1 --oneline

# one-time setup (if missing):
git worktree add ../CVE-Intel-deploy origin/main

# update clean deploy worktree:
cd ../CVE-Intel-deploy
git fetch origin
git checkout origin/main
```

Ensure compose build context points to clean worktree:

```bash
cd ~/cve-intel-vps
grep -n "context:" docker-compose.yml
# expected API context:
# context: /home/nixk2000/CVE-Intel-deploy
```

Rebuild and restart API container:

```bash
cd ~/cve-intel-vps
sudo docker compose build api
sudo docker compose up -d api
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep cveintel-api
sudo docker logs --since 5m cveintel-api
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
curl -sS -H "Accept-Encoding: gzip" -D - -o /tmp/intel_summary_gzip.json https://cve-intel.duckdns.org/api/intel-summary/2026 | grep -i -E "content-encoding|content-length|cache-control|vary"
```

Expected outcomes for latest API revision:

- `/api/intel-summary/2026` returns `200` (not `404`)
- cache headers are present on API responses as configured by backend route policy
- summary endpoint payload is materially smaller than full-year `/api/intel/2026`
- gzip compression is active for clients requesting it (`content-encoding: gzip`)

## 6) Rollback (If API restart fails)

```bash
cd ~/CVE-Intel-deploy
git fetch origin
git checkout <last-known-good-commit>
cd ~/cve-intel-vps
sudo docker compose build api
sudo docker compose up -d api
sudo docker ps --format "table {{.Names}}\t{{.Status}}" | grep cveintel-api
sudo docker logs --since 5m cveintel-api
```

After stabilization, return deploy worktree to tracked remote:

```bash
cd ~/CVE-Intel-deploy
git checkout origin/main
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

## 8) Common Failure Points

1. NVD request timeouts/retries causing scrape cycle overrun.
2. Validator query timeout under high DB load near end of scrape cycle.
3. GitHub API rate-limit volatility affecting mapping completeness/timing.
4. Transient DNS resolver failures (e.g., `lookup api.github.com ... 127.0.0.53:53: server misbehaving`) causing scrape cycle failure.
5. Backup/snapshot auth token drift causing push/publish failures.
6. Missing API service restart after code deploy, leaving old routes live.
7. Secret/env drift in `/etc/cve-intel.env` causing service startup failures.

DNS transient recovery steps:

```bash
sudo journalctl -u cveintel-scrape.service --since "-30 minutes" --no-pager
sudo systemctl restart cveintel-scrape.service
sudo journalctl -u cveintel-scrape.service --since "-10 minutes" --no-pager | grep -E "Validation PASSED|scrape cycle complete|ERROR"
sudo cat /var/log/cveintel/ops_health_status.json
```

Hardening: bounded automatic retries for scrape unit (recommended):

Tracked override file (repo source of truth):

- `deploy/systemd/cveintel-scrape.service.d/override.conf`

```bash
ssh nixk2000@172.175.241.146 'sudo systemctl cat cveintel-scrape.service | grep ExecStart'
scp deploy/systemd/cveintel-scrape.service.d/override.conf nixk2000@172.175.241.146:/tmp/cveintel-scrape-override.conf
ssh nixk2000@172.175.241.146 'sudo mkdir -p /etc/systemd/system/cveintel-scrape.service.d'
ssh nixk2000@172.175.241.146 'sudo install -m 644 /tmp/cveintel-scrape-override.conf /etc/systemd/system/cveintel-scrape.service.d/override.conf'
ssh nixk2000@172.175.241.146 'sudo systemctl daemon-reload'
ssh nixk2000@172.175.241.146 'sudo systemctl restart cveintel-scrape.service'
ssh nixk2000@172.175.241.146 'sudo systemctl show cveintel-scrape.service -p Restart -p RestartUSec -p StartLimitBurst'
```

## 9) Incident Response Pattern (6 Steps)

1. Detect and classify
- Confirm user-visible symptom and impacted surface (`/api`, dashboard, timers, snapshots).

2. Stabilize blast radius
- Pause/serialize risky jobs if needed (`systemctl stop` non-critical units) while preserving core availability.

3. Collect evidence
- Capture service status, recent journals, and status JSON files before changing multiple variables.

4. Apply smallest safe fix
- Prefer minimal reversible changes (single unit restart/config fix) over broad refactors in-incident.

5. Verify recovery
- Re-run endpoint + header checks and confirm service state returns `active (running)` or successful completion markers.

6. Record and prevent recurrence
- Append exact timeline/cause/fix to `MIGRATION_LOG.md`; update runbook/checks to prevent repeat incidents.
