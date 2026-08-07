# CVE-Intel Roadmap

This roadmap tracks execution on `main` (stable public version) and keeps work scoped to what can be shipped safely.

## Current baseline (August 2026)

- [x] `main` restored to stable static dashboard lineage
- [x] CI workflow restored
- [x] News + scrape workflows restored
- [x] Pages switched to GitHub Actions publishing mode
- [x] Migration work preserved separately on `vps-migration-wip`

## Now (P0: stabilization and reliability)

- [ ] Keep data freshness healthy for 72 hours
  - Success criteria:
  - News workflow remains green on hourly schedule.
  - Scrape workflow remains green on 6-hour schedule.
  - New commits continue landing in `data/news.json` and `data/2026.json`.
- [ ] Stabilize Pages deploys in Actions mode
  - Success criteria:
  - At least 2 consecutive successful Pages deploy runs.
  - Public URL serves expected static title/content from `main`.
- [ ] Refresh operational docs to match recovered architecture
  - Success criteria:
  - README/ops notes describe active workflows and required secrets.
  - No references that imply VPS runtime is active on `main`.

## Next (P1: data quality and triage improvements)

- [ ] Improve exploit correlation quality and de-dup logic
- [ ] Add source confidence scoring and display it in UI
- [ ] Add triage quick-actions in dashboard rows
- [ ] Add lightweight regression checks for JSON shape compatibility

## Later (P2: analytics and UX depth)

- [ ] CVE ↔ repository graph visualization
- [ ] Timeline analytics (severity, KEV, EPSS trend slices)
- [ ] Better mobile interaction polish for dashboard and news
- [ ] Exportable investigator reports (CSV/JSON bundle)

## Backlog exploration

- [ ] EPSS-first prioritization workflows
- [ ] KEV-first analyst views
- [ ] Alerting hooks (Slack/Telegram/Webhook) for freshness failures

## Release and branch policy

- `main`: stable, public-facing, GitHub Pages-compatible.
- `vps-migration-wip`: ongoing VPS/API migration experiments.
- Release tags remain semantic (`vX.Y.Z`) on `main` only after stability checks pass.
