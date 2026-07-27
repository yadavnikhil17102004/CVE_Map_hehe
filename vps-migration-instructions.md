# Migration Instructions: GitHub Actions + Pages → Azure VPS

## Context for Codex

This repository is a Go-based threat-intel pipeline:
- **Scrapers**: `cvemapping.go` (CVE-tagged GitHub repos), `nvd_scraper.go` (NVD/KEV/EPSS enrichment, 3 phases), `news_scraper.go` (RSS ingestion), `validate.go` (dataset integrity checks)
- **Automation**: `.github/workflows/scrape.yml` (every 6h — CVE mapping + NVD enrichment), `.github/workflows/news.yml` (every 1h — news only), `.github/workflows/ci.yml` (build/test on push/PR)
- **Data**: flat JSON files in `data/` (`data/<year>.json`, `data/nvd_intel_<year>.json`, `data/nvd_intel.json`, `data/news.json`), committed back to the repo by the workflows
- **Frontend**: static HTML (`index.html`, `dashboard.html`, `news.html`, `docs.html`) that `fetch()`s the JSON files directly, served via GitHub Pages

**Goal**: Move hosting + cron jobs to a self-managed Azure VPS with fixed billing, backed by Postgres, with a FastAPI service replacing direct JSON-file fetches. Keep GitHub for source control and CI only.

**Key constraint**: Use **dual-write** during migration — scrapers must keep writing the existing JSON files (safety net) *and* write to Postgres, until the new stack is verified stable. Do not remove the JSON-writing code path until explicitly instructed in Phase 9.

**Language choices**: Go stays for the scrapers (no rewrite — concurrency is a good fit for hitting multiple APIs). Python for the one-time migration script and the new API layer (FastAPI), since it keeps the door open for future NLP/news-correlation work and has low ceremony for a handful of endpoints.

Work through the phases in order. Do not skip ahead to Phase 6+ until Phase 5 verification has passed. At the end of each phase, report back what was done, what was verified, and any blockers before proceeding.

---

## Data Access Policy (Locked Decision)

This migration uses a **two-tier distribution model**:
- **Primary**: live API responses from FastAPI backed by Postgres on VPS (integration path for downstream consumers).
- **Secondary**: periodic bulk snapshot artifacts published as **GitHub Release assets** (offline/reproducibility path).

Important implementation constraints:
- Do **not** commit generated bulk datasets to git history (no weekly `data/*.json` commits to main branch).
- Use GitHub Releases for snapshot bundles (`.json.gz` or `.zip`) tagged by date (example: `snapshot-2026-07-20`).
- Keep JSON file output in runtime during dual-write phases as safety net, but treat those as operational artifacts, not versioned-history payloads.

This policy is intended to preserve API-first access for integrators while avoiding repository bloat and large-file history churn.

---

## Phase 1 — VPS Base Setup

**Objective**: A hardened, Docker-ready VPS reachable over a test subdomain, with the production domain untouched.

1. SSH into the Azure VPS. Create a non-root sudo user if one doesn't already exist; disable root SSH login.
2. Configure the firewall (ufw or Azure NSG) to allow only: 22 (SSH), 80 (HTTP), 443 (HTTPS).
3. Install Docker Engine + Docker Compose plugin.
4. Install Caddy (preferred, for automatic HTTPS) or Nginx + certbot as reverse proxy.
5. **No domain is owned yet.** Use the free wildcard DNS service `sslip.io` for the test hostname instead of a purchased domain — it automatically resolves any hostname encoding an IP to that IP, with no DNS configuration required. Use `172-175-241-146.sslip.io` as the test hostname (VPS IP: `172.175.241.146`).
6. Configure Caddy to serve on this hostname and obtain a real Let's Encrypt HTTPS certificate for it (sslip.io hostnames are publicly resolvable, so standard ACME HTTP-01 challenge works — no special config needed beyond setting the hostname in the Caddyfile).
7. Verify: hitting `https://172-175-241-146.sslip.io` returns a valid response with a trusted (non-self-signed) certificate.

**Note**: no production domain has been purchased yet. A real domain will be acquired and configured before Phase 8 (production cutover) — not needed before then.

**Deliverable to confirm before moving on**: VPS reachable via HTTPS on the test subdomain; Docker + Compose installed and working (`docker run hello-world` succeeds).

---

## Phase 2 — Postgres Setup

**Objective**: A running Postgres instance on the VPS with a schema mirroring the current JSON data shapes.

1. Add a Postgres service to a `docker-compose.yml` on the VPS (pin a specific Postgres version, e.g. 16). Use a named volume for data persistence. Store credentials in a `.env` file (not committed to git).
2. Inspect the actual shape of the existing JSON files to design the schema — read `data/<year>.json`, `data/nvd_intel_<year>.json`, and `data/news.json` from the repo to get exact field names before creating tables. Don't guess the schema; derive it from the real files.
3. Create tables approximating current structures, e.g.:
   - `cve_repos` (cve_id, repo_id, repo_name, repo_url, description, topics, has_code, age_days, year, discovered_at, ...)
   - `nvd_intel` (cve_id, cvss_score, cvss_vector, cwe, kev_flag, epss_score, epss_percentile, year, updated_at, ...)
   - `news_items` (id, title, url, source, tier, published_at, summary, ...)
   
   Adjust field names/types to match what's actually in the JSON — this is a starting point, not a spec to follow blindly.
4. Add appropriate indexes: `cve_id` on `cve_repos` and `nvd_intel`, `published_at` on `news_items`, and a `year` index on both CVE tables since the frontend queries by year.
5. Verify: can connect to Postgres from inside the VPS (e.g. `psql`), tables exist with correct columns.

**Deliverable to confirm before moving on**: Postgres running in Docker, schema created, connection verified.

---

## Phase 3 — One-Time Data Migration Script (Python)

**Objective**: Backfill all existing `data/*.json` content into Postgres.

1. Write a Python script (`migrate.py` or similar, in a `migration/` or `scripts/` folder — not shipped as part of the running app) using `psycopg2` or `SQLAlchemy` + the standard `json` module.
2. Script should:
   - Iterate over every `data/<year>.json` file found in the repo and upsert rows into `cve_repos`.
   - Iterate over every `data/nvd_intel_<year>.json` (and reconcile against `data/nvd_intel.json` if there are records only present in the full file) and upsert into `nvd_intel`.
   - Parse `data/news.json` and upsert into `news_items`.
   - Use `ON CONFLICT ... DO UPDATE` (upsert) so the script is safely re-runnable without creating duplicates.
   - Log a summary count per table at the end (rows inserted/updated) so the run is auditable.
3. Run the script against the Postgres instance from Phase 2.
4. Verify: row counts in Postgres roughly match record counts in the source JSON files (e.g. count CVEs per year in JSON vs. `SELECT COUNT(*) FROM cve_repos WHERE year = ...`).

**Deliverable to confirm before moving on**: Migration script run successfully once, Postgres populated, counts verified against source JSON.

---

## Phase 4 — Dual-Write in Go Scrapers

**Objective**: Scrapers write to Postgres *in addition to* their existing JSON output, without changing existing JSON-writing behavior.

1. In `cvemapping.go`, `nvd_scraper.go`, and `news_scraper.go`: locate the existing `-export-json` / file-write logic. Leave it completely untouched.
2. Add a Postgres client (`pgx` recommended over `lib/pq` for modern Go) and, immediately after each successful JSON write, perform the equivalent upsert into Postgres.
3. **Critical**: wrap Postgres writes in error handling that logs the failure but does **not** fail the overall job — a Postgres write failure must never block or break the JSON file output. The JSON files remain the safety net.
4. Add DB connection config via environment variables (host, port, user, password, dbname) — do not hardcode credentials.
5. Deploy the updated Go binaries to the VPS (via `git clone` + `go build`, or a Dockerfile if preferred).
6. Set up **systemd timers** (or cron, whichever Codex judges simpler to maintain) on the VPS replicating the existing schedules:
   - CVE mapping + NVD enrichment: every 6 hours
   - News scraper: every 1 hour
7. Run each job manually once first (not via the timer) to confirm it works end-to-end before wiring up the schedule.

**Deliverable to confirm before moving on**: Scrapers running on VPS on schedule, writing to both JSON files and Postgres, with Postgres write failures logged but non-fatal.

---

## Phase 4B — One-Time Historical CVE Metadata Backfill (2000–Present)

**Objective**: Build a complete long-range NVD/CVSS/EPSS metadata baseline in Postgres from year 2000 to present, independent of regular scrape scheduling.

Scope guardrails:
- This phase is **NVD + EPSS metadata only**.
- Do **not** include GitHub repo search backfill in this phase (that is a separate, lower-priority follow-on).
- Do not modify/disable the existing 6h/1h scraper timers.

1. Expand `nvd_intel` schema additively (no destructive changes, no dropping existing columns), based on real NVD API v2.0 response fields:
   - Separate CVSS v3.1/v3.0/v2 score/vector/severity columns.
   - `references` (`jsonb`)
   - `cpe_configurations` (`jsonb`)
   - `weaknesses` (`jsonb`) for full weakness payload, not just one CWE label.
   - `vendor_comments` (`jsonb`) when present.
   - `source_identifier`
   - `vuln_status`
   - `last_modified_date`
   - Any additional additive metadata needed to preserve fidelity.
   Record this as a tracked schema migration and log it in `MIGRATION_LOG.md`.
2. Fetch NVD historical data from `/rest/json/cves/2.0` using date-window pagination:
   - Process from `2000-01-01` through present.
   - Respect NVD window constraints (max 120-day range per request window).
   - Respect authenticated rate limits with `NVD_API_KEY` (50 req / 30s).
3. Use FIRST.org **bulk EPSS CSV export** to enrich EPSS in bulk (avoid per-CVE EPSS API calls in this phase).
4. Make the backfill resumable:
   - Persist checkpoint/progress state (window + pagination cursor + counters).
   - Restart resumes from checkpoint, not from the beginning.
5. Run detached so disconnects do not interrupt work:
   - systemd long-running service or tmux.
   - Emit progress logs periodically (for example: completed through year windows).
6. Expect `nvd_intel` to be much larger than `cve_repos`; this is normal for historical coverage.
7. Verification targets:
   - Final `nvd_intel` row count should be in the same order of magnitude as NVD published total CVE corpus.
   - Spot-check early-2000s CVEs for populated CVSS/CWE/reference/configuration metadata.
8. Document full run details, checkpoints, and verification outcomes in `MIGRATION_LOG.md`.

**Deliverable to confirm before moving on**: Historical NVD metadata backfill job completed (or actively running with resumable checkpoints and progress visibility), with schema expansion applied and verification evidence logged.

---

## Phase 5 — Verification Window

**Objective**: Confirm dual-write is trustworthy before anything reads from Postgres in production.

1. Let the dual-write run for several full cycles — at minimum, enough to cover a handful of the 1-hour news cycles and at least 2–3 of the 6-hour CVE/NVD cycles.
2. Write a small verification script (Python, reusing logic from Phase 3's migration script) that compares current `data/<year>.json` contents against current Postgres contents for the same year, and flags any mismatches (missing CVEs, mismatched fields, stale data).
3. Run this comparison after the verification window and resolve any discrepancies found.
4. Do not proceed to Phase 6 until this comparison passes cleanly on at least one CVE/NVD cycle and one news cycle.

**Deliverable to confirm before moving on**: Verification script shows Postgres data matches JSON output with no unresolved discrepancies.

---

## Phase 6 — FastAPI Service

**Objective**: A Python API reading from Postgres, returning JSON shaped identically to the existing static files (so the frontend needs minimal changes).

1. Scaffold a FastAPI app on the VPS (own directory, own Docker service in the compose file).
2. Implement endpoints mirroring current data access patterns found in the frontend:
   - `GET /api/cve/{year}` → same shape as `data/{year}.json`
   - `GET /api/intel/{year}` → same shape as `data/nvd_intel_{year}.json`
   - `GET /api/news` → same shape as `data/news.json`
   - `GET /api/search?q=...` → supports the dashboard's global search (currently done by fetching many yearly files client-side — this endpoint should do that filtering server-side in Postgres instead)
3. Create and use a dedicated **read-only Postgres role** for API reads (separate from scraper writer credentials).
4. Add server-side pagination/filtering for `/api/search`.
5. Add basic rate limiting on all endpoints.
6. Enable response compression (gzip).
7. Expose OpenAPI docs at `/docs` and keep `openapi.json` reachable.
8. Confirm the response JSON shape byte-for-byte matches (or is a strict superset of) what the frontend currently expects — check field names against actual `fetch()` usage in `index.html`, `dashboard.html`, `news.html`, `docs.html` before finalizing the response models.
9. Verify: hitting each endpoint manually (curl / browser) returns valid, correctly-shaped JSON matching current data.
10. Add/confirm API documentation section in README for integrators (endpoint list, example query params, rate-limit guidance if any).
11. Keep this API as the primary public data interface; do not reintroduce "commit datasets to repo history" as a distribution path.

**Deliverable to confirm before moving on**: FastAPI service running on VPS, all endpoints verified against real data.

---

## Phase 7 — Frontend Cutover (on test subdomain only)

**Objective**: Frontend served from the VPS, reading from the new API, tested on the subdomain before touching production DNS.

1. Copy the static frontend files (`index.html`, `dashboard.html`, `news.html`, `docs.html`, and any assets/`web/data` references) to the VPS, served by Caddy/Nginx.
2. Update all `fetch('data/...')` calls to point at the FastAPI endpoints instead (`fetch('/api/...')`). Keep the update minimal and mechanical since Phase 6 was designed to match existing shapes.
3. Reverse-proxy `/api/*` requests to the FastAPI service; serve everything else as static files.
4. Test the full site on the test subdomain: home page charts, dashboard filtering/search, news page, docs page — confirm each against what the current GitHub Pages site shows for the same data.

**Deliverable to confirm before moving on**: Test subdomain fully functional, matching current production site's behavior and data.

---

## Phase 8 — Public Hostname Cutover (No Paid Domain)

**Objective**: Use a permanent free hostname (`cve-intel.duckdns.org`) instead of purchasing a domain.

1. Configure DuckDNS auto-update on the VPS (systemd timer every 5 minutes) using values from `/etc/cve-intel.env` (`DUCKDNS_SUBDOMAIN`, `DUCKDNS_TOKEN`), never hardcoded.
2. Point Caddy at `cve-intel.duckdns.org`, provision real Let's Encrypt HTTPS, and verify end-to-end on `https://cve-intel.duckdns.org`.
3. Keep `172-175-241-146.sslip.io` as optional fallback until Phase 7 validation is complete.
4. Monitor closely for the first 24–48 hours: check scrape/news jobs run, API responds correctly, frontend loads correctly on the DuckDNS hostname.
5. Leave GitHub Pages deployment in place but inactive (don't delete yet) as rollback safety.

**Deliverable to confirm before moving on**: `cve-intel.duckdns.org` serving from VPS over valid HTTPS, stable for 48 hours.

---

## Phase 9 — Launch Cleanup + Repository Prep

**Objective**: preserve legacy history, make the repo launch-ready, and keep only the workflows/docs that match the VPS architecture.

1. Create and push tag `legacy-static-v1` at the pre-cleanup `main` baseline so the old static-era build remains permanently accessible.
2. Remove stale scheduled workflow files tied to commit-back architecture (`.github/workflows/scrape.yml`, `.github/workflows/news.yml`, `sync.yml.bak` if present). Keep `ci.yml` for CI.
3. Update `README.md` to reflect live VPS architecture (Postgres + FastAPI + Caddy), current hostname, `/docs`, snapshot release path, ethics/disclaimer notice, and links to roadmap + legacy tag.
4. Capture deferred trust/risk and news-intelligence work in `ROADMAP.md` so investigation output is preserved as planned backlog.
5. **Only if Phase 6/7 have been stable for a meaningful window** (multiple real scrape/news cycles with no regressions): remove JSON dual-write from scrapers and remove stale repo data payloads from `main`.
6. If stability window is not yet sufficient, explicitly defer step 5 and log that decision in `MIGRATION_LOG.md` (do not force cutover).

**Deliverable to confirm before moving on**: repository launch artifacts updated, legacy tag published, CI-only workflow set, and dual-write removal decision explicitly justified (done or deferred).

---

## Phase 9.5 — Pre-Launch Checklist

Run and report each item individually before public launch sign-off:

1. **Functional**: site pages load, API endpoints return expected schema, dashboard/news interactions work.
2. **Security**: rate limiting verified with real `429`, read-only DB role verified (write denied), no debug traceback exposure in public API error paths.
3. **Secret hygiene**: no service passes secrets via CLI args (`ps`/journal audit clean for token-bearing flags), and any previously exposed token is rotated before sign-off.
4. **Ops readiness**: scrape/news timers healthy, backup/snapshot jobs healthy, DuckDNS updater healthy, HTTPS valid.
   - Include reboot-readiness checks for backup job ordering/readiness (Postgres available before `pg_dump`).
5. **Legal/ethical**: disclaimer/ethical-use notice present in README (and optionally site footer/docs).
6. **Documentation**: `README.md`, `MIGRATION_LOG.md`, `ROADMAP.md`, and migration instructions reflect current reality.

---

## Phase 10 — Backups & Alerting

**Objective**: Operational safety net now that the VPS is the single point of failure.

1. Set up a daily `pg_dump` cron job on the VPS, uploading the dump to Azure Blob Storage (cheap, durable).
2. Add a basic health check: a script (cron'd) that verifies the CVE/NVD job ran within the last ~7 hours and the news job ran within the last ~90 minutes; on failure, send an alert (webhook to Discord/Slack, or email) rather than failing silently.
3. Document the rollback procedure in the repo's README: how to point DNS back at GitHub Pages and re-enable the old workflows if the VPS has a serious outage.
4. Implement a weekly snapshot export job that:
   - reads from Postgres,
   - writes compressed artifact(s) (`.json.gz` or `.zip`),
   - publishes to GitHub Releases (not branch commits),
   - records release tag + checksum in `MIGRATION_LOG.md`.

**Deliverable to confirm before moving on**: Backups running daily and verified restorable; alerting confirmed working (trigger a test failure and confirm the alert fires).

---

## General notes for Codex throughout

- Never guess field names or schema shapes — always read the actual current files (`data/*.json`, the `fetch()` calls in the HTML files, the Go struct definitions in the scrapers) before writing code that depends on their structure.
- Do not delete or overwrite the existing JSON-writing logic until Phase 9 explicitly calls for it.
- Do not touch the production DNS record until Phase 8.
- Report status and any blockers at the end of each phase before starting the next one.
