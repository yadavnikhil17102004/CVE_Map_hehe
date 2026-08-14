# CVE-Intel Roadmap

This roadmap tracks execution on `main` (stable public version) and keeps work scoped to what can be shipped safely.

## Current baseline (August 2026)

- [x] `main` restored to stable static dashboard lineage
- [x] CI workflow restored
- [x] News + scrape workflows restored
- [x] Pages switched to GitHub Actions publishing mode
- [x] Migration work preserved separately on `vps-migration-wip`

## Live status snapshot (as of 2026-08-14 09:25 UTC)

- [x] CI recovered to green on latest run (`#61`, head `4b55df1f`)
- [x] News workflow healthy (hourly runs green in latest verification window)
- [x] Scrape workflow previously had intermittent commit/push failures (`#665`, `#667`), with subsequent successful run (`#668`)
- [x] Pages deploy healthy on latest runs (`#16` success)
- [x] Public Pages URL serves expected static title (`CVE Map — Aggregated GitHub Exploits`)
- [x] Performance benchmark harness added for factual optimization validation (`scripts/perf/dashboard-perf-compare.js`)
- [x] Operations log added: `docs/operations/2026-08-14-stability-and-performance-log.md`

## Recently completed (2026-08-14)

- [x] README workflow/secrets documentation refreshed
- [x] Scrape/news push race hardening (`concurrency` + retry/backoff/rebase-safe push)
- [x] Dashboard optimization benchmark harness added (`scripts/perf/dashboard-perf-compare.js`)
- [x] Incident and recovery operations log added (`docs/operations/2026-08-14-stability-and-performance-log.md`)

## P0 Reliability Track (in progress)

- [ ] Keep data freshness healthy for 72 hours
  - Owner: `@nikhilyadav`
  - Target date: `2026-08-17`
  - Status: `in progress`
  - Success criteria: no failed news runs for 72 consecutive hours.
  - Success criteria: scrape failures limited to <= 1 transient failure per 24h.
  - Success criteria: at least 3 successful scrape runs in a row.
  - Success criteria: at least 24 successful news runs in a row.

- [x] Stabilize Pages deploys in Actions mode
  - Owner: `@nikhilyadav`
  - Completed: `2026-08-14`
  - Evidence: consecutive successful deployments (`#14`, `#15`, `#16`)

- [ ] Remove scrape commit race/flakiness
  - Owner: `@nikhilyadav`
  - Target date: `2026-08-17`
  - Status: `mitigation shipped, observation window active`
  - Success criteria: scrape `Commit & Push New Datasets` step succeeds on consecutive scheduled runs.
  - Success criteria: workflow no longer fails after successful scrape/build due to git push/rebase contention.

- [ ] Re-enable browser smoke as blocking in CI
  - Owner: `@nikhilyadav`
  - Target date: `2026-08-18`
  - Status: `non-blocking temporarily; diagnostics uploading`
  - Exit condition: 10 consecutive successful smoke executions on `main` before removing `continue-on-error`.

## P0 Observability Track (in progress)

- [ ] Add workflow triage runbook
  - Owner: `@nikhilyadav`
  - Target date: `2026-08-15`
  - Status: `in progress`
  - Success criteria: diagnosis matrix exists for `ci`, `news`, `scrape`, and `pages`.
  - Success criteria: includes "rerun vs fix-first" guidance.

- [ ] Add data freshness guardrail check
  - Owner: `@nikhilyadav`
  - Target date: `2026-08-16`
  - Status: `planned`
  - Success criteria: CI utility validates staleness thresholds for CVE/news files.
  - Success criteria: failures provide clear remediation text.

- [x] Refresh operational docs to match recovered architecture
  - Completed: `2026-08-14`
  - Evidence: README + CONTRIBUTING + operations log updated, including performance benchmark protocol.

## Next execution queue (ordered)

- [ ] Task 1: Add runbook for workflow triage
  - Add quick diagnosis matrix for `scrape`, `news`, `pages` failures.
  - Include "when to rerun" vs "when to commit and redeploy".
- [ ] Task 2: Add data freshness guardrail check
  - Add a CI utility script that validates staleness thresholds for news/CVE files.
  - Fail with clear error messages when thresholds are exceeded.
- [ ] Task 3: Improve scrape resiliency observability
  - Add better error logging around token/rate-limit/API failures in scrape workflow.
  - Keep non-destructive behavior (skip commit on no delta).
- [ ] Task 4: Roadmap-to-issue alignment
  - Open/refresh GitHub issues for each P1 item and link them here.

## Reliability SLOs (rolling 7-day targets)

- CI workflow success rate >= 95%
- Pages deploy success rate >= 99%
- Hourly news freshness lag <= 2 hours
- CVE dataset freshness lag <= 8 hours
- Scrape workflow success rate >= 90%

## Next 48 hours plan

- [ ] 1) Publish triage runbook and link it from README
  - Validation: runbook exists and covers `ci`, `news`, `scrape`, `pages`.

- [ ] 2) Land freshness guardrail script and wire it into CI
  - Validation: synthetic stale fixture fails; current live dataset passes.

- [ ] 3) Observe scrape/news reliability window and decide smoke policy
  - Validation: collect run stats and either keep non-blocking smoke or move back to blocking based on 10-run threshold.

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
- [ ] Browser smoke restored to blocking with stable pass window.
- [ ] P1 work can begin without branch/pipeline churn.
