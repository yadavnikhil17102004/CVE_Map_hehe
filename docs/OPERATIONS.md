# Operations Runbook

This runbook is for day-to-day operations and incident triage on the VPS.

## Core systemd units

- `cveintel-scrape.service` / `.timer`
- `cveintel-news.service` / `.timer`
- `cveintel-backup.service` / `.timer`
- `cveintel-public-snapshot.service` / `.timer`
- `cveintel-ops-health.service` / `.timer`
- `cveintel-telegram-bot.service`
- `cveintel-duckdns.service` / `.timer`

## Quick health checks

```bash
systemctl list-timers --all | grep cveintel
systemctl status cveintel-scrape.service --no-pager
systemctl status cveintel-news.service --no-pager
systemctl status cveintel-ops-health.service --no-pager
```

## Log checks

```bash
journalctl -u cveintel-scrape.service --since "-24 hours" --no-pager
journalctl -u cveintel-news.service --since "-24 hours" --no-pager
journalctl -u cveintel-backup.service --since "-7 days" --no-pager
journalctl -u cveintel-public-snapshot.service --since "-14 days" --no-pager
journalctl -u cveintel-ops-health.service --since "-24 hours" --no-pager
```

## Status files

```bash
cat /var/log/cveintel/ops_health_status.json
cat /var/log/cveintel/backup_status.json
cat /var/log/cveintel/public_snapshot_status.json
cat /var/log/cveintel/duckdns_status.json
```

## Manual triggers

```bash
sudo systemctl start cveintel-scrape.service
sudo systemctl start cveintel-news.service
sudo systemctl start cveintel-backup.service
sudo systemctl start cveintel-public-snapshot.service
sudo systemctl start cveintel-ops-health.service
```

## Common failure points

1. NVD large-window reads timing out under load.
2. Validation query timeout too low for large table scans.
3. GitHub API volatility/rate behavior affecting repo count churn.
4. Snapshot/backup auth token issues.

## Incident response pattern

1. Confirm service terminal state (`Result`, `ActiveState`).
2. Capture exact failing log lines (phase + operation + error).
3. Validate DB connectivity and row sanity.
4. Apply targeted fix only after isolating root cause.
5. Re-run one manual cycle, then verify next timer-fired cycle.
6. Record findings in `MIGRATION_LOG.md`.
