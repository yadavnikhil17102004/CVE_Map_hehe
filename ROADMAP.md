# CVE-Intel Roadmap

This roadmap tracks execution on `main` (stable public version) and keeps work scoped to what can be shipped safely.

## Current baseline (August 2026)

- [x] `main` restored to stable static dashboard lineage
- [x] CI workflow restored
- [x] News + scrape workflows restored
- [x] Pages switched to GitHub Actions publishing mode
- [x] Migration work preserved separately on `vps-migration-wip`

## Live status snapshot (as of 2026-08-08)

- [x] CI latest run green (`31175475665`)
- [x] News workflow healthy (latest hourly runs green, most recent: `31250977132`)
- [x] Scrape workflow mostly healthy but intermittent failures remain
  - Example success: `31233288448`
  - Example failure: `31244973802` (build step passed; failed in commit/push step)
- [x] Pages deploy healthy on recent pushes (latest stable window green)
- [x] Public Pages URL serves expected static title (`CVE Map — Aggregated GitHub Exploits`)
- [x] Latest CVE data commit landed (`8de2c54`, `2026-08-08T02:38:42Z`)
- [x] Latest news payload updated (`2026-08-08T09:37:47Z`, 95 articles)

## Now (P0: stabilization and reliability)

- [ ] Keep data freshness healthy for 72 hours
  - Success criteria: no failed news runs for 72 consecutive hours.
  - Success criteria: scrape failures limited to <= 1 transient failure per 24h.
  - Success criteria: at least 3 successful scrape runs in a row.
  - Success criteria: at least 24 successful news runs in a row.
- [ ] Stabilize Pages deploys in Actions mode
  - Success criteria: 2 consecutive successful Pages deploy runs on new pushes.
  - Success criteria: no `deployment_queued` timeouts/cancellations in that window.
- [ ] Remove scrape commit race/flakiness
  - Success criteria: scrape `Commit & Push New Datasets` step succeeds on consecutive scheduled runs.
  - Success criteria: workflow no longer fails after successful scrape/build due to git push/rebase contention.
- [ ] Refresh operational docs to match recovered architecture
  - Success criteria: README documents all active workflows and required secrets.
  - Success criteria: `main` docs clearly separate stable branch from VPS migration branch.

## Next execution queue (ordered)

- [ ] Task 1: Update README workflow section
  - Add triggers/cadence for `ci.yml`, `news.yml`, `scrape.yml`, `pages.yml`.
  - Document secrets: `SYNC_TOKEN`, `NVD_API_KEY`.
- [ ] Task 2: Add runbook for workflow triage
  - Add quick diagnosis matrix for `scrape`, `news`, `pages` failures.
  - Include "when to rerun" vs "when to commit and redeploy".
- [ ] Task 3: Add data freshness guardrail check
  - Add a CI utility script that validates staleness thresholds for news/CVE files.
  - Fail with clear error messages when thresholds are exceeded.
- [ ] Task 4: Improve scrape resiliency
  - Add better error logging around token/rate-limit/API failures in scrape workflow.
  - Keep non-destructive behavior (skip commit on no delta).
- [ ] Task 4A: Harden scrape commit/push step
  - Add bounded retry/backoff around `git pull --rebase` + `git push`.
  - Ensure job exits cleanly on no-op/no-diff states.
  - Keep behavior idempotent with concurrent news commits.
- [ ] Task 5: Roadmap-to-issue alignment
  - Open/refresh GitHub issues for each P1 item and link them here.

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

## Definition of done for this phase

- [ ] 72h stability window achieved across CI/news/scrape.
- [ ] Pages deploys consistently green on push.
- [ ] Documentation reflects the recovered architecture without ambiguity.
- [ ] P1 work can begin without branch/pipeline churn.
