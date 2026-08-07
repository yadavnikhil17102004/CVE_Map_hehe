# CVE-Intel Roadmap

This roadmap tracks execution on `main` (stable public version) and keeps work scoped to what can be shipped safely.

## Current baseline (August 2026)

- [x] `main` restored to stable static dashboard lineage
- [x] CI workflow restored
- [x] News + scrape workflows restored
- [x] Pages switched to GitHub Actions publishing mode
- [x] Migration work preserved separately on `vps-migration-wip`

## Live status snapshot (as of 2026-08-07)

- [x] Latest CI run is green (`31152749048`)
- [x] Latest news runs are green (`31168730674`, `31163931165`, `31156927456`)
- [x] Latest scrape run is green (`31157057620`)
- [x] Latest Pages deploy run is green (`31152749208`)
- [x] Public Pages URL serves expected static title (`CVE Map — Aggregated GitHub Exploits`)
- [x] Latest CVE data commit landed (`aa2987a`, `2026-08-07T08:09:32Z`)
- [x] Latest news payload updated (`2026-08-07T10:07:00Z`, 95 articles)

## Now (P0: stabilization and reliability)

- [ ] Keep data freshness healthy for 72 hours
  - Success criteria: no failed news/scrape runs for 72 consecutive hours.
  - Success criteria: at least 3 successful scrape runs in a row.
  - Success criteria: at least 24 successful news runs in a row.
- [ ] Stabilize Pages deploys in Actions mode
  - Success criteria: 2 consecutive successful Pages deploy runs on new pushes.
  - Success criteria: no `deployment_queued` timeouts/cancellations in that window.
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
