# Workflow Triage Runbook

Use this runbook when GitHub Actions workflows fail on `main`.

## Fast triage order

1. Check latest run status for `CI`, `Deploy GitHub Pages`, `Hourly News Intelligence Scraper`, `Continuous Exploit Scraper`.
2. Identify first failing step (not just workflow conclusion).
3. Decide `rerun` vs `fix-first` using matrix below.
4. If fix-first, land minimal change and re-run.
5. Record incident summary in operations log when failure pattern repeats.

## Failure matrix

### CI (`.github/workflows/ci.yml`)

- Typical failures:
  - Browser smoke instability
  - Dependency/setup transient issues
- Rerun when:
  - Setup/network step transiently fails once.
- Fix-first when:
  - Same smoke/test assertion fails >= 2 consecutive runs.
  - Build/validation step fails deterministically.
- Current policy:
  - Browser smoke is non-blocking temporarily and uploads artifacts.
  - Return to blocking only after stability threshold is met.

### Deploy GitHub Pages (`.github/workflows/pages.yml`)

- Typical failures:
  - `deployment_queued` stalls
  - cancelled deployment due to newer run
- Rerun when:
  - Single queue/cancel event with no source/config changes.
- Fix-first when:
  - Repeated queue/cancel over consecutive runs.
  - Permissions/source mode regression appears.
- Verify:
  - Repository Pages source is `GitHub Actions`.

### Hourly News Intelligence Scraper (`.github/workflows/news.yml`)

- Typical failures:
  - Push/rebase contention on `main`
  - Source feed/network transient errors
- Rerun when:
  - One-off fetch/network issue.
- Fix-first when:
  - `Commit & Push New Data` fails repeatedly.
  - No updates for >2 expected hourly windows.
- Verify:
  - `data/news.json` latest commit timestamp.

### Continuous Exploit Scraper (`.github/workflows/scrape.yml`)

- Typical failures:
  - Long scrape succeeds but commit/push step fails
  - API/rate-limit constraints
- Rerun when:
  - Single transient API failure.
- Fix-first when:
  - Repeated failures in `Commit & Push New Datasets`.
  - Data freshness lag exceeds target window.
- Verify:
  - Latest `data/YYYY.json` and `data/nvd_intel_YYYY.json` commit timestamps.

## Data freshness checks

- News freshness target: <= 2 hours lag.
- CVE freshness target: <= 8 hours lag.

If lag exceeds target:
1. Check latest run conclusions.
2. Check failing step.
3. Trigger manual run only after root cause classification.

## Smoke policy

- Current: non-blocking smoke with artifact upload.
- Exit criteria to restore blocking:
  - 10 consecutive successful smoke executions on `main`.
  - No recurring deterministic assertion failures in that window.

