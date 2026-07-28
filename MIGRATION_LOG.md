# Migration Log

This file is the persistent, phase-by-phase execution record for migrating CVE-Intel from GitHub Actions + GitHub Pages to Azure VPS + Postgres + FastAPI.

## 2026-07-20 — Phase 1 (VPS Base Setup)

### Scope
- Harden VPS access and networking.
- Install runtime dependencies (Docker/Compose, Caddy).
- Expose a test hostname over HTTPS without touching production domain.

### Actions Completed
- Connected to Azure VPS (`172.175.241.146`) as `nixk2000` (Ubuntu 24.04.4 LTS).
- Enforced SSH hardening:
  - Added `/etc/ssh/sshd_config.d/99-hardening.conf` with `PermitRootLogin no`.
  - Reloaded SSH daemon after config validation (`sshd -t`).
- Configured firewall (`ufw`):
  - Default incoming `deny`, outgoing `allow`.
  - Allowed only `22/tcp`, `80/tcp`, `443/tcp`.
- Installed services:
  - `docker.io`
  - `docker-compose-v2`
  - `caddy`
- Enabled and started `docker` and `caddy` services.
- Configured Caddy for test hostname:
  - `172-175-241-146.sslip.io`
  - Static placeholder served from `/var/www/cve-intel`.

### Verification
- `docker run --rm hello-world` succeeded.
- `ufw status` showed only 22/80/443 allowed.
- Caddy configuration validated and reloaded successfully.
- HTTPS check passed:
  - `https://172-175-241-146.sslip.io` returned `HTTP/2 200`.
  - Placeholder page rendered ("it works").

### Decisions
- Used `sslip.io` wildcard test hostname to avoid production DNS changes in early phases.

---

## 2026-07-20 — Phase 2 (Postgres Setup)

### Scope
- Deploy Postgres in Docker with persistent storage.
- Derive schema from actual repository JSON shapes (no guessed fields).
- Add indexes aligned with expected query patterns.

### Actions Completed
- Created VPS project directory: `~/cve-intel-vps`.
- Added:
  - `~/cve-intel-vps/.env`
  - `~/cve-intel-vps/docker-compose.yml`
  - `~/cve-intel-vps/schema.sql`
- Deployed `postgres:16` container (`cveintel-postgres`) with:
  - Named volume `cveintel_postgres_data`
  - Healthcheck (`pg_isready`)
  - Bound only to loopback (`127.0.0.1:5432`)
- Created schema:
  - `cve_repos`
  - `nvd_intel`
  - `news_items`

### Schema Derivation Inputs
- `data/<year>.json`:
  - `year`, `cves[]`, `cves[].cve_id`, `cves[].repositories[]`, repo owner fields.
- `data/nvd_intel_<year>.json` compact keys:
  - `s,v,d,c,w,k,r,p,u,e` (+ `q` seen in full file)
- `data/news.json`:
  - `last_updated`, `articles[]` with `title,link,description,pub_date,source,tier,image_url`.

### Indexes Added
- `cve_repos`:
  - PK `(cve_id, repo_id)`
  - `idx_cve_repos_cve_id`
  - `idx_cve_repos_year`
  - `idx_cve_repos_pushed_at`
- `nvd_intel`:
  - PK `(cve_id)`
  - `idx_nvd_intel_cve_id`
  - `idx_nvd_intel_year`
  - `idx_nvd_intel_cvss_score`
- `news_items`:
  - PK `(id)`, unique `(link)`
  - `idx_news_items_published_at`
  - `idx_news_items_tier`

### Verification
- Container healthy.
- `psql` connection verified (`current_database = cveintel`).
- Tables present and indexes verified in `pg_indexes`.

---

## 2026-07-20 — Phase 3 (One-Time Data Migration)

### Scope
- Build rerunnable migration script for JSON -> Postgres.
- Perform first full backfill.
- Verify row-count parity against source JSON.

### Actions Completed
- Created migration script:
  - `scripts/migration/migrate.py`
- Script behavior:
  - Upserts all `data/<year>.json` repos into `cve_repos`.
  - Upserts all `data/nvd_intel_<year>.json` into `nvd_intel`, then fills only-missing IDs from `data/nvd_intel.json`.
  - Upserts `data/news.json` into `news_items`.
  - Uses `ON CONFLICT DO UPDATE` for rerunnable idempotent writes.
  - Logs inserted/updated totals.
- Deployed script to VPS and executed against Postgres.

### NVD Compact Key Mapping Used
- `s` -> `cvss_score`
- `v` -> `severity`
- `d` -> `description`
- `c` -> `cvss_vector`
- `w` -> `cwe`
- `k` -> `kev_flag`
- `r` -> `source`
- `p` -> `published_date`
- `u` -> `status`
- `e` -> `epss_score`
- `q` -> `products`

### Migration Run Summary
- `cve_repos`: inserted `17,716`, updated `0`
- `nvd_intel`: inserted `197,885`, updated `0`
- `news_items`: inserted `95`, updated `0`

### Verification
- Postgres counts:
  - `cve_repos` = `17,716`
  - `nvd_intel` = `197,885`
  - `news_items` = `95`
- JSON source counts matched exactly:
  - `json_repo_rows` = `17,716`
  - `json_nvd_rows` = `197,885`
  - `json_news_rows` = `95`
- Year-level sanity checks matched:
  - `2025` CVEs = `1,311`
  - `2026` CVEs = `1,337`

### Security / Credential Hygiene
- Rotated Postgres password before Phase 4.
- Updated VPS `~/cve-intel-vps/.env`.
- Applied new DB credential at role level and verified login.
- Added `.env` and `.env.*` to repository `.gitignore` to prevent accidental commits.
- Stored an off-VPS credential backup in local macOS Keychain (`service: cveintel-postgres-vps`, `account: nixk2000@172.175.241.146`).

---

## 2026-07-20 — Phase 4 (Dual-Write in Go Scrapers + VPS Scheduling)

### Scope
- Keep JSON writing logic untouched.
- Add Postgres upsert alongside existing JSON writes in all scrapers.
- Make DB write failures non-fatal.
- Deploy to VPS and wire 6h/1h schedules via systemd timers.

### Code Changes Completed
- Updated `cvemapping.go`:
  - Added Postgres upsert after successful `data/<year>.json` write.
  - DB config from env: `DATABASE_URL` or `POSTGRES_*`.
  - On DB error: log warning and continue (JSON path remains successful).
- Updated `nvd_scraper.go`:
  - Added Postgres upsert after `writeIntelByYear(...)`.
  - Includes compact key projection (`s,v,d,c,w,k,r,p,u,e,q` -> table columns).
  - On DB error: log warning and continue.
- Updated `news_scraper.go`:
  - Added Postgres upsert after `data/news.json` write.
  - On DB error: log warning and continue.
- Dependency updates:
  - Added `github.com/jackc/pgx/v5/pgxpool` and related modules.
  - `go.mod` / `go.sum` refreshed.
- Local build verification passed:
  - `go build cvemapping.go`
  - `go build nvd_scraper.go`
  - `go build news_scraper.go`
  - `go build validate.go`

### VPS Deployment Actions
- Installed Go 1.25.5 on VPS (matches project Go requirement).
- Copied updated source to `~/CVE-Intel` and built binaries on VPS.
- Created secure runtime env file: `/etc/cve-intel.env`
  - Contains `POSTGRES_*`, `SYNC_TOKEN`, `NVD_API_KEY`, etc.
- Added runner scripts:
  - `/usr/local/bin/cveintel-scrape.sh` (6h cycle: cvemapping current+last year, nvd_scraper, validate)
  - `/usr/local/bin/cveintel-news.sh` (hourly news cycle)
- Added systemd units:
  - `cveintel-scrape.service` + `cveintel-scrape.timer`
  - `cveintel-news.service` + `cveintel-news.timer`
- Enabled timers via `systemctl enable`.

### Manual Run Verification
- `cveintel-news.service`:
  - Ran successfully after fixing env-file permissions.
  - JSON output updated (`data/news.json`) and Postgres dual-write confirmed:
    - Log: `Postgres upsert complete for news_items: 95 rows`
  - Some upstream feed warnings observed (429 / malformed feed / cert mismatch on one source), but job completed.
- `cveintel-scrape.service`:
  - Initial run failed fast by design while `SYNC_TOKEN` was unset (explicit + intentional guard, no silent partial behavior).
  - After secure secret population in `/etc/cve-intel.env`, manual full-cycle run succeeded (`status=0/SUCCESS`).
  - Verified in logs for the successful run:
    - `Exported 1343 CVEs to data/2026.json`
    - `Postgres upsert complete for year 2026: 2984 repo rows`
    - `Exported 1311 CVEs to data/2025.json`
    - `Postgres upsert complete for year 2025: 3164 repo rows`
    - `Wrote data/nvd_intel_*.json` (all year-scoped outputs) + `data/nvd_intel.json`
    - `Postgres upsert complete for nvd_intel: 197885 rows`
    - `Validation PASSED`
    - `scrape cycle complete`

### Data/DB Post-Run Checks
- File mtimes (successful manual run):
  - `data/2026.json` updated at `2026-07-20 10:09:41 UTC`
  - `data/2025.json` updated at `2026-07-20 10:12:02 UTC`
  - `data/nvd_intel.json` updated at `2026-07-20 10:55:03 UTC`
- Postgres row counts after manual run:
  - `cve_repos` = `17730`
  - `nvd_intel` = `197885`
  - `news_items` = `101`
- Year-level check in Postgres:
  - 2025: `1311` CVEs, `3165` repo rows
  - 2026: `1343` CVEs, `2985` repo rows

### Decisions / Notes
- Kept JSON write path untouched exactly as migration constraint requires.
- Added explicit guard in 6h script for missing `SYNC_TOKEN` to avoid ambiguous failures.
- Started/verified timers after manual-run validation:
  - `cveintel-news.timer` active (hourly; next 12:00 UTC at setup time)
  - `cveintel-scrape.timer` active (every 6h; next 11:12 UTC at setup time)

### Phase Status
- **Phase 4 complete.** Dual-write is active, manual runs validated, and schedule automation is running.

---

## 2026-07-20 — Phase 4B (Historical NVD Metadata Backfill 2000–Present)

### Scope
- One-time NVD/CVSS/EPSS metadata backfill from 2000 to present.
- No GitHub repo search backfill in this phase.
- Existing 6h/1h schedulers left unchanged.

### Actions Completed
- Added formal Phase 4B instructions in `vps-migration-instructions.md`.
- Added additive schema migration:
  - `scripts/migration/phase4b_nvd_schema.sql`
- Added resumable bulk backfill script:
  - `scripts/migration/backfill_nvd_history.py`
- Applied schema migration on VPS Postgres:
  - Added CVSS v3.1/v3.0/v2 split fields.
  - Added `nvd_references`, `cpe_configurations`, `weaknesses`, `vendor_comments`.
  - Added `source_identifier`, `vuln_status`, `last_modified_date`, `epss_percentile`.
  - Added indexes on `last_modified_date`, `source_identifier`, `vuln_status`.
  - Added checkpoint/run tracking tables:
    - `nvd_backfill_checkpoint`
    - `nvd_backfill_runs`
- Deployed detached systemd one-shot style runner:
  - Service: `cveintel-historical-backfill.service`
  - Wrapper: `/usr/local/bin/cveintel-historical-backfill.sh`
  - Restart policy: `on-failure`

### Operational/Resumability Notes
- The service is resumable via DB checkpoint (`nvd_backfill_checkpoint`).
- Multiple manual restarts were performed while fixing EPSS ingestion and secret handling; each restart resumed from checkpoint (no reset to 2000).
- Secrets hardening fix applied:
  - Removed DB/API secrets from CLI args (now sourced from `/etc/cve-intel.env` only).
  - `systemctl status` no longer exposes sensitive values.
- Live status file support added:
  - Writes current state to `/var/log/cveintel/backfill_status.json`.
  - File is overwritten on each completed window (current snapshot only).
  - Emits lifecycle state values: `running`, `completed`, `failed`.

### EPSS Bulk Source Handling
- Initial EPSS URL (`epss.empirical.security`) failed DNS resolution on VPS.
- Switched to reachable bulk source family:
  - `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
  - fallback `https://epss.cyentia.com/epss_scores-current.csv.gz`
- Fixed parser to skip FIRST metadata comment line in CSV.
- Current EPSS load result at service start:
  - `loaded 349491 EPSS rows`

### Progress Checkpoint (as of 2026-07-20 12:07 UTC)
- Service status: `active (running)`
- Checkpoint table:
  - `window_start = 2010-07-07`
  - `window_end = 2010-11-03`
  - `processed_cves = 41223`
  - `status = running`
- Current `nvd_intel` row count:
  - `198263`
- Coverage snapshot (partial/in-progress):
  - `rows_with_last_modified = 42656`
  - `rows_with_cvss = 42278`
  - `rows_with_refs = 42656`
  - `rows_with_epss = 175777`

### Live Status File Verification
- Created/permissioned status directory:
  - `/var/log/cveintel` (owned by service user `nixk2000`)
- Verified file creation:
  - `/var/log/cveintel/backfill_status.json`
- Verified overwrite/update on next window completion:
  - First sample (`last_updated=2026-07-20T12:17:08Z`, `processed_cves_total=53547`)
  - Next sample (`last_updated=2026-07-20T12:19:16Z`, `processed_cves_total=55149`)

### Phase Status
- **Phase 4B in progress** (detached backfill running with checkpoints + logs).

---

## 2026-07-20 — Data Access Decision + Progress Snapshot

### Data Storage / Distribution Decision (Locked)
- **Source of truth remains VPS Postgres** (runtime data layer).
- **FastAPI is the primary integration surface** for users/consumers.
- **GitHub repo history will not be used for bulk data commits** going forward (no recurring large JSON commits).
- **Secondary bulk access path** will be weekly compressed snapshots published as **GitHub Release assets** (date-tagged), after API shape is finalized in Phase 6+.

### Why This Decision
- Avoids repository growth and large-blob git history churn.
- Preserves a stable live API for integrators.
- Still provides downloadable offline snapshots for researchers/reproducibility.

### Backfill Live Status Snapshot (user-provided check)
- Status file: `/var/log/cveintel/backfill_status.json`
- Snapshot timestamp: `2026-07-20T13:42:00Z`
- Current window: `2024-04-24` -> `2024-08-21`
- `processed_cves_total`: `248980`
- `nvd_intel_row_count`: `321263`
- `epss_rows_loaded`: `349491`
- `errors_last_24h`: `0`
- `status`: `running`

### Next Expected Log Update
- On backfill completion: record final counts, early-2000s spot checks, and mark Phase 4B complete.

---

## 2026-07-21 — Incident: Scrape Timer Misconfiguration (`*:0/6`)

### Incident Summary
- Found a scheduling bug in `/etc/systemd/system/cveintel-scrape.timer`:
  - Incorrect: `OnCalendar=*:0/6`
  - This normalizes to `*-*-* *:00/6:00` (every 6 minutes), not every 6 hours.
- This increased scrape frequency risk for GitHub Search + NVD traffic and unnecessary VPS load.

### Immediate Remediation
- Patched timer unit on VPS:
  - `OnCalendar=0/6:00:00`
- Executed:
  - `systemctl daemon-reload`
  - `systemctl restart cveintel-scrape.timer`
- Verification:
  - `systemd-analyze calendar "0/6:00:00"` -> normalized as `*-*-* 00/6:00:00`
  - `systemctl list-timers --all` and `systemctl status cveintel-scrape.timer` confirmed corrected schedule semantics.
  - After the 06:00 UTC trigger completed (`cveintel-scrape.service` finished `status=0/SUCCESS` at `06:27:50 UTC`), timer showed next trigger at `12:00:00 UTC` (hours away, not minutes).

### Impact Audit (since 2026-07-20)
- `cveintel-scrape.service` start count from journal:
  - `11` starts.
- Start timestamps showed frequent runs (example sequence):
  - `11:12`, `11:59`, `12:47`, `13:36`, `14:26`, `15:15`, `16:34`, `17:34`, `18:34` UTC (2026-07-20), then `05:26` UTC (2026-07-21).
- Practical effect observed:
  - Not true concurrent overlap; systemd serialized runs while service was active.
  - However, cadence was still far too aggressive versus intended 6h (near back-to-back after each completion).

### Rate-Limit / API Fallout Check
- Scrape logs reviewed for explicit GitHub/NVD limit signals:
  - No GitHub `HTTP 429`, `HTTP 403`, or abuse/rate-limit warning pattern found in `cveintel-scrape.service` logs.
  - NVD had intermittent upstream instability/timeouts (`context deadline exceeded`, `HTTP 503`) during some windows.
- Live credential health probes (non-secret):
  - GitHub rate endpoint returned healthy remaining quota:
    - `core_limit=5000`, `core_remaining=4956`
    - `search_limit=30`, `search_remaining=30`
  - NVD keyed probe returned `HTTP 200`.
- Conclusion:
  - No current evidence of token/key ban or hard rate-limit lockout.
  - Primary incident impact was unnecessary frequency/load risk and extra scrape churn.

### Additional Status Captured
- Phase 4B historical backfill status file now reports completion:
  - `/var/log/cveintel/backfill_status.json`
  - `status=completed`
  - `processed_cves_total=366077`
  - `nvd_intel_row_count=367650`

---

## 2026-07-21 — Backup/Release Automation (Private Backup Repo + Public Weekly Releases)

### Scope
- Implement daily private backup automation for disaster recovery.
- Implement weekly public snapshot release automation (GitHub Releases, no branch commits).
- Decide Git LFS requirement from actual measured dump size (not assumptions).

### Measured DB Dump Size (Decision Input)
- Ran `pg_dump -Fc` against VPS Postgres (`cveintel`) and measured artifact size:
  - `208,051,747` bytes (`~199 MB`)
- Decision:
  - **Git LFS required** for dump files (exceeds GitHub 100 MB hard file limit).
- VPS dependency installed:
  - `git-lfs` (`git-lfs/3.4.1`)

### Automation Installed on VPS
- Scripts:
  - `/usr/local/bin/cveintel-backup.sh`
  - `/usr/local/bin/cveintel-public-snapshot.sh`
- Systemd units:
  - `/etc/systemd/system/cveintel-backup.service`
  - `/etc/systemd/system/cveintel-backup.timer`
  - `/etc/systemd/system/cveintel-public-snapshot.service`
  - `/etc/systemd/system/cveintel-public-snapshot.timer`
- Timers enabled:
  - `cveintel-backup.timer` -> daily at `02:30 UTC`
  - `cveintel-public-snapshot.timer` -> weekly Sunday at `03:00 UTC`

### Daily Private Backup Job Behavior
- Intended target repo:
  - `github.com/yadavnikhil17102004/CVE-Server_backup` (private)
- Job actions:
  - Dump Postgres in custom format (`-Fc`) as `backups/db/latest.dump`.
  - Track dump paths with Git LFS when size threshold requires.
  - Keep weekly dated snapshots on Sundays: `backups/db/weekly/YYYY-MM-DD.dump`.
  - Prune weekly snapshots older than 56 days.
  - Sync operational files:
    - Caddyfile
    - `cveintel-*.service` / `cveintel-*.timer`
    - `docker-compose.yml`, `schema.sql`
    - `scripts/migration/*`
    - `MIGRATION_LOG.md` (if present on VPS repo clone)
  - Maintain `SECRETS_MANIFEST.md` (locations only, no values).
  - Write status file:
    - `/var/log/cveintel/backup_status.json`

### Weekly Public Snapshot Job Behavior
- Intended target repo:
  - `github.com/yadavnikhil17102004/CVE-Intel` (public)
- Job actions:
  - Export Postgres tables as **streamed NDJSON gzip** files to avoid OOM:
    - `cve_repos.ndjson.gz`
    - `nvd_intel.ndjson.gz`
    - `news_items.ndjson.gz`
  - Package as `snapshot-YYYY-MM-DD.tar.gz`.
  - Publish GitHub Release tag `snapshot-YYYY-MM-DD` and upload artifact.
  - Compute SHA256 and append release/checksum note to VPS-side `MIGRATION_LOG.md`.
  - Write status file:
    - `/var/log/cveintel/public_snapshot_status.json`

### Manual Validation (Current State)
- `cveintel-backup.service` manual run:
  - Fails safely with explicit status when token is missing.
  - Status file now reports:
    - `status=failed`
    - `message=missing BACKUP_GH_PAT in /etc/cve-intel.env`
- `cveintel-public-snapshot.service` manual run:
  - Fails safely with explicit status when token is missing.
  - Status file now reports:
    - `status=failed`
    - `message=missing PUBLIC_RELEASE_GH_PAT in /etc/cve-intel.env`
- Prior OOM issue in public snapshot export (from full-table `json_agg`) was remediated by switching to streamed `COPY ... row_to_json ... | gzip` exports.

### Required Secret Follow-Up (Owner Action)
- Add to `/etc/cve-intel.env` on VPS:
  - `BACKUP_GH_PAT` -> fine-grained PAT with write access to private backup repo only.
  - `PUBLIC_RELEASE_GH_PAT` -> token with release publish rights on public repo.
- After secrets are set:
  - rerun both services once manually and confirm `status=completed`.

### Post-Secret Verification (Completed)
- Owner provided both required PATs in `/etc/cve-intel.env`.
- `cveintel-public-snapshot.service` manual run succeeded:
  - `/var/log/cveintel/public_snapshot_status.json`:
    - `status=completed`
    - `tag=snapshot-2026-07-21`
    - `checksum_sha256=d15bac410624384db90977430673a025a971a9df0acf8edb1303dc00120da98f`
  - Release tag verified present on public repo: `snapshot-2026-07-21`.
- `cveintel-backup.service` required two follow-up script fixes after secret injection:
  - Guard optional `scripts/migration` path when absent on VPS.
  - Handle first-run bootstrap against an empty private repository (`main` branch init, no `origin/HEAD` assumption).
- Final manual `cveintel-backup.service` run succeeded:
  - Service exited `status=0/SUCCESS`.
  - `/var/log/cveintel/backup_status.json`:
    - `status=completed`
    - `dump_size_bytes=208053079`
    - `lfs_required=true`
    - `files_synced=12`
  - Private backup repo push confirmed:
    - commit: `9b3e21c`
    - LFS-tracked dump present: `backups/db/latest.dump`.

### Current Scheduled State
- `cveintel-news.timer`: hourly.
- `cveintel-scrape.timer`: every 6 hours (`0/6:00:00`), with next trigger hours away as expected.
- `cveintel-backup.timer`: daily `02:30 UTC`.
- `cveintel-public-snapshot.timer`: Sunday `03:00 UTC`.

### Backup Artifact Integrity Verification (Deep Check)
- Performed **fresh-clone LFS retrieval** in a separate directory (not the push worktree):
  - verify path: `/tmp/cveintel-lfs-verify-1784636487/repo`
  - ran: `git lfs pull`
  - ran: `git lfs fsck` -> `ok`
  - verified dump exact size:
    - expected `208053079`
    - actual `208053079`
  - verified LFS object mapping:
    - `66b35d0ddf7e11fecb9d28c54bc0a4e9ad8eb5c189b1b55b9cd1d82f8fe53850 * backups/db/latest.dump`
- Performed restore-readability check:
  - ran: `pg_restore --list backups/db/latest.dump`
  - result: `ok` (dump is structurally valid and readable)

### Public Snapshot Delivery Verification (Unauthenticated)
- Verified public GitHub Release asset accessibility and integrity without auth:
  - asset: `snapshot-2026-07-21.tar.gz`
  - download HTTP status: `200`
  - downloaded size: `152733042` bytes
  - SHA256 expected:
    - `d15bac410624384db90977430673a025a971a9df0acf8edb1303dc00120da98f`
  - SHA256 actual:
    - `d15bac410624384db90977430673a025a971a9df0acf8edb1303dc00120da98f`
  - integrity result: `match=true`

---

## 2026-07-21/22 — Phase 5 Verification Window (JSON vs Postgres Dual-Write)

### Verification Script Added
- Added `scripts/migration/verify_dual_write.py` (Phase 5 verifier).
- Purpose:
  - Compare `data/<year>.json` vs `cve_repos` for matching years.
  - Compare `data/nvd_intel_<year>.json` vs `nvd_intel` by `cve_id`.
  - Compare `data/news.json` vs `news_items` by `link`.
- Scope guard:
  - Compares only where JSON counterpart exists.
  - Does not treat historical-only Postgres coverage as mismatch.

### Baseline Run
- Command label: `baseline`
- Report: `/var/log/cveintel/phase5_verify_baseline.json`
- Generated at: `2026-07-21T12:45:27Z`
- Result:
  - `overall_ok=false`
  - `cve_repos`: checked `17757`, missing `0`, extra `4`, field mismatches `0`
  - `nvd_intel`: checked `253538`, missing `0`, extra `0`, field mismatches `0`
  - `news_items`: checked `95`, missing `0`, extra `0`, field mismatches `0`

### During Verification Window (Operational Incident)
- VM became deallocated in Azure unexpectedly; SSH dropped.
- Restarted VM and re-verified timer/service health.
- Noted a service regression discovered/fixed during this window:
  - `/etc/cve-intel.env` permissions had been tightened to `600 root:root`, causing `cveintel-news.service` and `cveintel-scrape.service` startup failures (`Permission denied`).
  - Restored readable service-safe mode: `640 root:nixk2000`.
  - News and scrape services resumed successful execution.

### Post-Live-Cycle Run
- Command label: `post_live_cycle`
- Report: `/var/log/cveintel/phase5_verify_post_cycle.json`
- Generated at: `2026-07-22T05:51:04Z`
- Result:
  - `overall_ok=false`
  - `cve_repos`: checked `17782`, missing `0`, extra `23`, field mismatches `0`
  - `nvd_intel`: checked `253538`, missing `0`, extra `0`, field mismatches `0`
  - `news_items`: checked `95`, missing `0`, extra `0`, field mismatches `0`

### Findings / Blocker
- Phase 5 remains **open** (not complete).
- Only failing area is `cve_repos`:
  - DB contains stale extra rows not present in latest JSON snapshots.
  - Pattern indicates insert/update-only dual-write without reconciliation deletes for removed repos.
- `nvd_intel` and `news_items` comparisons are clean across both runs.

### Next Fix Required for Phase 5 Completion
- Add reconciliation behavior for `cve_repos` dual-write path:
  - after yearly write/upsert, delete rows in `cve_repos` for that year (or CVE scope) that are no longer present in current JSON export.
- Re-run verifier after next live cycle; require one clean `overall_ok=true` run to mark Phase 5 complete.

### Root-Cause Investigation (No Hard Deletes Implemented)
- Performed requested investigation before any delete-reconciliation implementation.

1. Extra-row existence check against GitHub (post-cycle sample set)
- Source set: `23` extra rows from `/var/log/cveintel/phase5_verify_post_cycle.json`.
- Queried GitHub by repository ID (`GET /repositories/{id}`) for each row.
- Result split:
  - `13` repos returned `HTTP 200` (still exist).
  - `10` repos returned `HTTP 404` (gone/private/removed).
- Interpretation:
  - Not a pure comparison bug.
  - Extra rows are a mixed set of:
    - historical repos no longer present in current search result set,
    - and repos that genuinely no longer resolve on GitHub.

2. Comparison-scoping audit
- Verified `verify_dual_write.py` scope logic:
  - `cve_repos` compares `data/<year>.json` against `cve_repos WHERE year=<same year>`.
  - `nvd_intel` compares by `cve_id` from `data/nvd_intel_<year>.json` only.
  - `news_items` compares `data/news.json` by `link`.
- Confirmed there is no year cross-wiring in current script path causing the observed `cve_repos` extras.

3. Back-to-back `cvemapping` consistency test (same year, same token)
- Ran `cvemapping` twice consecutively for 2025:
  - run1: `1310` CVEs, `3162` repo rows
  - run2: `1310` CVEs, `3162` repo rows
  - delta: `0` (`only_run1=0`, `only_run2=0`)
- Ran `cvemapping` twice consecutively for 2026:
  - run1: `1379` CVEs, `3047` repo rows
  - run2: `1379` CVEs, `3047` repo rows
  - delta: `0` (`only_run1=0`, `only_run2=0`)
- Interpretation:
  - No short-window run-to-run volatility was observed in this test.
  - `cve_repos` drift appears to be accumulation of previously seen repos vs latest snapshot, not immediate per-run randomness.

### Investigation Conclusion
- Hard deletes are still **not** applied.
- Evidence supports preserving historical sightings (archival goal) and avoiding destructive reconciliation by default.
- If cleanup semantics are needed later, use non-destructive state tracking (`last_seen_in_scrape_at` / tombstone-style fields) rather than physical row deletion.

### Phase 5 Closure Update (2026-07-23)
- Approved archival verification semantics were implemented:
  1. JSON subset enforcement (`JSON ⊆ DB`) is the hard failure condition.
  2. `extra_in_db` is informational (historical sightings preserved).
  3. Added non-destructive `last_seen_in_scrape_at` tracking for `cve_repos`.
- Schema follow-up applied on VPS Postgres:
  - Migration: `scripts/migration/phase5_cve_repos_last_seen.sql`
  - Column added/backfilled: `cve_repos.last_seen_in_scrape_at`
  - Index added: `idx_cve_repos_last_seen_in_scrape_at`
- `cvemapping` dual-write updated to set `last_seen_in_scrape_at=NOW()` on insert/update.
- Final verifier run:
  - label: `phase5_archival_semantics`
  - report: `/var/log/cveintel/phase5_verify_archival.json`
  - generated at: `2026-07-23T07:47:58Z`
  - `overall_ok=true`
  - table summaries:
    - `cve_repos`: checked `17814`, missing `0`, field mismatches `0`, extra `39` (informational)
    - `nvd_intel`: checked `253538`, missing `0`, field mismatches `0`, extra `0`
    - `news_items`: checked `95`, missing `0`, field mismatches `0`, extra `0`
- Note:
  - EPSS score drift-only rows (`1644`) are tracked as informational because EPSS is time-variant and can differ between JSON snapshot timing and DB timing without indicating structural dual-write breakage.

### Phase Status
- **Phase 5 complete** under approved archival semantics.

---

## 2026-07-23 — Phase 6 Execution (FastAPI + DuckDNS Hostname)

### Scope Completed
- Implemented FastAPI service in `api/` and deployed to VPS Docker Compose as `cveintel-api`.
- Added permanent free public hostname using DuckDNS (`cve-intel.duckdns.org`) with automatic DNS update timer.
- Updated Caddy reverse proxy to serve static site + API + FastAPI docs over HTTPS.

### FastAPI Build/Deploy
- Added files:
  - `api/main.py`
  - `api/requirements.txt`
  - `api/Dockerfile`
- VPS compose update (`~/cve-intel-vps/docker-compose.yml`):
  - Added `api` service, bound to `127.0.0.1:8000`, depends on healthy Postgres.
  - `api` reads env from `/etc/cve-intel.env` and uses `POSTGRES_HOST=postgres`.
- Container status verified:
  - `cveintel-api` running (`Up`), proxied via Caddy.

### Phase 6 Security/Performance Requirements (Implemented)
- Read-only DB role created and enforced:
  - Role: `cveintel_api`
  - Grants: `CONNECT`, `USAGE` on `public`, `SELECT` on `cve_repos`, `nvd_intel`, `news_items`
  - Default privileges updated to grant future table `SELECT`
  - Write-block test with API role returned expected `permission denied for schema public`
- Pagination/filtering on `/api/search`:
  - Supports `page`, `per_page`, optional `year`, optional `severity`, optional `kev`
- Rate limiting:
  - Implemented with `slowapi` on all endpoints
- Response compression:
  - GZip middleware enabled in FastAPI
  - Verified response header: `content-encoding: gzip` on large API response
- OpenAPI docs:
  - `/docs` and `/openapi.json` now reachable through Caddy

### Endpoints Implemented
- `GET /api/cve/{year}`
- `GET /api/intel/{year}`
- `GET /api/news`
- `GET /api/search`
- `GET /api/health`

### Live Verification (DuckDNS Host)
- Host HTTPS:
  - `https://cve-intel.duckdns.org` returns `HTTP/2 200`
- API health:
  - `https://cve-intel.duckdns.org/api/health` returns `{"ok":true,"service":"cve-intel-api"}`
- Sample route checks:
  - `/api/cve/2026` → `year=2026`, `cves=1388`
  - `/api/intel/2026` → `entries=34646`
  - `/api/news?limit=95` → `articles=95`
  - `/api/search?q=log4j&page=1&per_page=3` → `total=16`, `returned=3`

### DuckDNS Automation
- Added updater script and timer on VPS:
  - Script: `/usr/local/bin/cveintel-duckdns.sh`
  - Service: `/etc/systemd/system/cveintel-duckdns.service`
  - Timer: `/etc/systemd/system/cveintel-duckdns.timer` (`OnCalendar=*:0/5`)
- Status file (current-state overwrite pattern):
  - `/var/log/cveintel/duckdns_status.json`
- Latest observed status:
  - `status=success`, `response=OK`, hostname `cve-intel.duckdns.org`

### Caddy Routing Changes
- Caddyfile now serves both `cve-intel.duckdns.org` and `172-175-241-146.sslip.io`.
- Routing:
  - `/api/*` -> FastAPI
  - `/docs*`, `/openapi.json`, `/redoc*` -> FastAPI
  - all other paths -> static file server (`/var/www/cve-intel`)
- ACME issuance for DuckDNS completed successfully in Caddy logs (`certificate obtained successfully`).

### Issues Found During Phase 6
- Initial `/api/search` returned HTTP 500 due SQL clause join bug (missing `OR` separators).
- Fixed in `api/main.py`, redeployed container, and re-verified endpoint success.

### Status
- **Phase 6 complete** on backend/API + hostname infrastructure.
- **Phase 7 remains pending** (frontend fetch cutover from `data/...` to `/api/...`).

---

## 2026-07-23 — Phase 7 Frontend Cutover (DuckDNS Host)

### Scope Completed
- Updated frontend fetch paths from static JSON files (`data/...`) to live API routes (`/api/...`) in:
  - `index.html`
  - `dashboard.html`
  - `news.html`
  - `docs.html`
- Updated dashboard API link from static file path to API endpoint (`/api/cve/{year}`).
- Deployed updated static frontend files to VPS web root: `/var/www/cve-intel`.

### Frontend Fetch Migration (Mechanical)
- Home page:
  - `data/news.json` -> `/api/news`
  - `data/<year>.json` -> `/api/cve/<year>`
  - `data/nvd_intel_<year>.json` -> `/api/intel/<year>`
- Dashboard page:
  - `data/<year>.json` -> `/api/cve/<year>`
  - `data/nvd_intel_<year>.json` -> `/api/intel/<year>`
  - `data/news.json` -> `/api/news`
  - cross-year search year loads now call `/api/cve/<year>`
- News page:
  - `data/news.json` -> `/api/news`
- Docs page:
  - `data/<year>.json` -> `/api/cve/<year>`
  - `data/nvd_intel_<year>.json` -> `/api/intel/<year>`
  - sample curl snippets updated to API routes

### Caddy Routing Fix During Phase 7
- Found route collision: `/docs*` reverse-proxy rule captured `docs.html` and caused `404` for site docs page.
- Fixed by narrowing API docs proxy paths to exact:
  - `/docs`, `/docs/`, `/openapi.json`, `/redoc`, `/redoc/`
- Post-fix verification:
  - `https://cve-intel.duckdns.org/docs.html` -> `200`
  - `https://cve-intel.duckdns.org/docs` -> `200`
  - `https://cve-intel.duckdns.org/openapi.json` -> `200`

### Live Validation Checks
- Served page status:
  - `/index.html` -> `200`
  - `/dashboard.html` -> `200`
  - `/news.html` -> `200`
  - `/docs.html` -> `200`
- Deployed HTML content checks (live host copies):
  - no remaining `fetch('data/...')` usage found
  - `/api/...` fetch usage present in all four pages
- API backend remained healthy throughout cutover (`/api/health` OK).

### Operational Note (DuckDNS Token)
- DuckDNS updater timer/service remain healthy (`status=success`, `response=OK`).
- Rotation verification currently reports token still equal to previously exposed value; project owner needs to confirm a new token was saved in `/etc/cve-intel.env` and then re-run rotation verification.

### Status
- **Phase 7 frontend cutover complete** (frontend now API-backed on VPS hostname).
- Pending operational hardening confirmation: DuckDNS token rotation verification.

---

## 2026-07-23 — Phase 9 Launch Cleanup (Repo + Docs) and Dual-Write Decision

### Completed in this phase

- Created annotated legacy preservation tag and pushed:
  - `legacy-static-v1`
- Removed old scheduled GitHub workflow files from `main`:
  - `.github/workflows/scrape.yml`
  - `.github/workflows/news.yml`
  - `.github/workflows/sync.yml.bak`
- Kept `.github/workflows/ci.yml` as the active workflow.
- Rewrote `README.md` to reflect current VPS architecture:
  - FastAPI + Postgres + Caddy
  - public hostname and API docs paths
  - snapshot distribution model
  - ethics/disclaimer notice
  - links to roadmap + migration docs
- Replaced `ROADMAP.md` with deferred Part 5/6 backlog details:
  - repo trust/risk scoring model
  - news intelligence upgrade path (CVE extraction, clustering, classification, trending)
- Updated `vps-migration-instructions.md`:
  - Phase 9 now reflects launch cleanup sequencing
  - added Phase 9.5 pre-launch checklist categories

### Dual-write removal decision (explicit)

- Decision: **deferred for now**.
- Reason:
  - `nvd_scraper.go` still has a hard dependency on local `data/*.json` CVE files for targeted backfill (`collectMissingCVEs`) and currently rebuilds/reads `data/nvd_intel.json` during runs.
  - Removing JSON writes immediately would change scraper behavior and could silently reduce enrichment quality unless scraper logic is first refactored to source target CVEs from Postgres directly.
  - Phase 6/7 are recently completed; keeping JSON dual-write for an additional stabilization window lowers operational risk.

### Required follow-up before true Postgres-only cutover

1. Refactor `nvd_scraper.go` targeted backfill source from filesystem to Postgres.
2. Update/replace `validate.go` checks (currently JSON-file based) with API/DB-native validation.
3. Re-run Phase 9.5 checklist after that refactor, then remove JSON writes/data artifacts intentionally.

### Phase 9.5 Pre-launch checklist run (2026-07-23)

1. Functional
- Pages: `/`, `/index.html`, `/dashboard.html`, `/news.html`, `/docs.html` -> `200`.
- API routes: `/api/cve/2026`, `/api/intel/2026`, `/api/news?limit=3`, `/api/search?...` -> `200`.
- `/api/health` returned `429` during intentional burst test window, then returned `200` after limiter window reset.

2. Security
- Rate limiting: verified with burst test (`200=60`, `429=15` on `/api/health`).
- Read-only DB role: verified write denial (`permission denied for schema public`).
- Error-response hygiene: invalid parameter request returns controlled `400` JSON (`severity must be one of ...`), no traceback exposed.
- Observation/risk: current scrape process command line includes token argument in process/journal context; should be remediated by removing secret-bearing CLI args in a follow-up hardening step.

3. Ops readiness
- DuckDNS updater timer healthy; status file shows `success` + `OK`.
- Backup job had earlier boot-time failure (Postgres not yet accepting local socket) but was manually rerun successfully; `backup_status.json` now `completed`.
- Public snapshot status file shows last successful release (`snapshot-2026-07-21`) and checksum.
- TLS certificate valid for `cve-intel.duckdns.org` (Let's Encrypt, valid Jul 23 -> Oct 21 2026).
- Scrape/news timers are firing; scrape cycle was observed active during checklist run.

4. Legal/ethical
- README includes explicit ethical-use and safety notice.

5. Documentation
- README, ROADMAP, MIGRATION_LOG, and migration instructions updated to reflect current architecture and deferred dual-write-removal decision.

---

## 2026-07-23 — Urgent Secret-Exposure Incident Response (Scrape Token) + Backup Boot Resilience

### Incident scope and findings

1. Exposed token and source
- Token class: GitHub sync token (`SYNC_TOKEN`, used for `cvemapping` GitHub API auth).
- Root cause: `/usr/local/bin/cveintel-scrape.sh` passed token on CLI:
  - `./cvemapping -github-token "${SYNC_TOKEN}" ...`
- Runtime proof captured: `ps` showed `./cvemapping -github-token github_pat_...` (redacted in logs/chat).

2. Historical journal persistence check
- Global journal scan summary:
  - `-github-token` matches: `4`
  - `github_pat_` prefix matches: `1`
  - `ghp_` prefix matches: `1`
  - `apiKey=` matches: `0`
- Investigated matching lines:
  - `-github-token` lines were command-history/audit entries from manual investigation commands and prior scripted checks.
  - `github_pat_/ghp_` match came from a grep command string itself (pattern text), not a persisted token value.
- Result: no confirmed persisted raw token value found in `journalctl` output.

3. Private backup repo contamination check
- Scanned `/opt/cveintel-private-backup/repo` (excluding `.git`, dump/gz artifacts) for:
  - `github_pat_`, `ghp_`, `-github-token`, `SYNC_TOKEN=`, `NVD_API_KEY=`, `DUCKDNS_TOKEN=`, `BACKUP_GH_PAT=`
- Result: no matches.
- Conclusion: no evidence that exposed token value was synced into the private backup repository.

### Remediation applied

1. Removed CLI secret dependency path
- `cvemapping.go` updated to accept GitHub token from env fallback when `-github-token` is omitted:
  - `GITHUB_TOKEN`, then `SYNC_TOKEN`.
- VPS scrape script rewritten to env-only token flow:
  - `export GITHUB_TOKEN="${SYNC_TOKEN}"`
  - `./cvemapping -export-json -year ... -page all`
  - removed `-github-token` arguments.

2. Verification after fix
- Runtime argv probe now shows:
  - `./cvemapping -year 2026 -page 1`
  - `cvemapping_args_contains_-github-token=no`
- Confirms token no longer appears in process arguments for cvemapping runs.

### Required owner action (still pending)

- Because token was exposed in process argv before remediation, treat current `SYNC_TOKEN` as potentially compromised.
- Owner must rotate `SYNC_TOKEN` in GitHub, update `/etc/cve-intel.env`, and restart/verify scrape service.

### Additional hardening done in same response

- Backup boot-time resilience improved:
  - `/usr/local/bin/cveintel-backup.sh` now waits for Docker Postgres container readiness (`pg_isready`, up to 150s) before running `pg_dump`.
- Live verification:
  - Manual `cveintel-backup.service` run succeeded post-patch.
  - `/var/log/cveintel/backup_status.json` reported `status=completed`, dump size recorded, push succeeded.

---

## 2026-07-23 — JSON-Removal Follow-on (In Progress): Postgres-first backfill + DB-native validation

### Implemented

1. `nvd_scraper.go` targeted backfill source refactor
- Phase 2 now sources candidate CVE IDs from Postgres (`cve_repos`) via new `collectMissingCVEsFromPostgres(...)`.
- Matching logic preserved:
  - include CVEs missing from dictionary
  - include unscored (`score == 0`) CVEs
  - retry stale `Deferred` entries older than 30 days
- JSON scan (`data/*.json`) remains only as explicit fallback if Postgres source is unavailable or empty.

2. `validate.go` file-based checks replaced with DB-native checks
- Removed dependency on:
  - `data/YYYY.json`
  - `data/nvd_intel.json`
  - `data/nvd_intel_YYYY.json`
- New validation now checks Postgres directly:
  - `cve_repos` row count + distinct CVEs
  - `nvd_intel` row count, required fields, KEV count, EPSS coverage threshold
  - year coverage in `cve_repos` and `nvd_intel`
  - `news_items` row presence
- Keeps explicit pass/fail semantics and summary output for scheduled runs.

### Local compile verification
- `go build ./nvd_scraper.go` passed.
- `go build ./validate.go` passed.

### Next
- Deploy updated source/binaries to VPS.
- Run a scrape-cycle smoke check to confirm:
  - Phase 2 logs Postgres-sourced targeted backfill path
  - validation step passes using DB-only logic
  - no regressions in dual-write behavior.

### VPS verification status (current)

- Deployed:
  - `nvd_scraper` binary rebuilt with Postgres-first targeted backfill source.
  - `nvd_scraper.go` and `validate.go` synced to VPS.
- `validate.go` execution on VPS now **passes** with DB-native checks.
  - Notes:
    - `27` intel rows have tiny required-field gaps (`0.0073%`) and are treated as warning-level.
    - `24201` rows have expected missing severity for non-scored/rejected statuses (warning-level informational).
- Manual trigger verification after PAT rotation:
  - `cveintel-scrape.service`: `result=success`
  - `cveintel-backup.service`: `result=success`
  - `cveintel-public-snapshot.service`: `result=success`
  - Status files confirm backup and release completion.

### Final redacted secret-verification pass

- Recent journal scan (last 20 minutes):
  - `-github-token` matches: `0`
  - `github_pat_` matches: `0`
  - `ghp_` matches: `0`
- Runtime argv check:
  - no `cvemapping` process carried token-bearing CLI args.

---

## 2026-07-23 — Final JSON Cutover (Postgres-only paths)

### Pre-removal live-cycle proof (requested gate)

- Manual `cveintel-scrape.service` run was triggered on refactored code and observed end-to-end through:
  - `cvemapping` (2026 + 2025) upsert path
  - `nvd_scraper` Phase 1 completion
  - `nvd_scraper` Phase 2 with explicit Postgres sourcing:
    - `Targeted backfill source: Postgres cve_repos (7869 candidate CVEs)`
    - `Found 1419 CVEs to backfill (missing or unscored)`
- Before/after DB movement during this proof window:
  - `cve_repos`: `17869` -> `17871`
  - `distinct cve_repos.cve_id`: `7916` -> `7917`
  - `nvd_intel`: `367650` -> `367650`
  - `news_items`: `290` -> `295`
- Fresh `validate.go` run during proof window: **PASSED**.

### Final removal executed

1. `cvemapping.go`
- Removed JSON file output dependency from export path.
- `-export-json` path now performs Postgres upsert only (no `data/<year>.json` writes).

2. `nvd_scraper.go`
- Removed JSON baseline load (`data/nvd_intel.json`).
- Removed JSON write/fallback path (`data/nvd_intel.json` + `data/nvd_intel_<year>.json`).
- Added Postgres baseline loader for dictionary bootstrap.
- Removed filesystem fallback scanner for Phase 2; targeted backfill source is Postgres-only.
- Postgres upsert failures are now fatal for integrity (no silent JSON fallback).

3. `news_scraper.go`
- Removed `data/news.json` writing.
- News ingest now persists to Postgres only.

4. `validate.go`
- Already DB-native from prior step; retained as Postgres-only validator.

### Post-cut verification

- DB validation: **PASSED** (`validate.go`).
- `cvemapping` smoke:
  - `Postgres upsert complete for year 2026`
  - `Export complete (Postgres-only)`
- `nvd_scraper` smoke:
  - `Loaded 367650 existing signatures from Postgres`
- Manual service checks after cut:
  - `cveintel-news.service`: `Result=success` (`Postgres upsert complete for news_items: 95 rows`)
  - `cveintel-backup.service`: `Result=success` (private backup push succeeded)
  - `cveintel-public-snapshot.service`: `Result=success` (release published)

### Note

- The long-running manual scrape proof cycle remained active for an extended NVD/EPSS processing window during observation; no failure state was observed, and Postgres-sourced Phase 2 behavior was confirmed from logs.

---

## 2026-07-24 — Phase 10 Alerting (Design Logged Before Implementation)

### Trigger for Phase 10 kickoff

- Production-impacting incident observed: VM repeatedly found deallocated due an Azure auto-shutdown schedule (`Microsoft.DevTestLab/schedules/shutdown-computevm-CVE-server`).
- Root cause has been disabled, but this incident validated need for proactive alerting rather than manual discovery.

### Phase 10 design (single notification channel)

1. VM power-state alert (off-box / Azure-native)
- Implement Azure Monitor alerting that fires when VM is deallocated/stopped.
- Use Activity Log signal on VM operations (deallocate/powerOff) so alert still works even when VM itself is down.
- Route to one central channel via Azure Action Group.

2. Scrape/news freshness alert (on-box checker)
- Add periodic health checker on VPS:
  - alert if latest scrape completion age > 7 hours
  - alert if latest news completion age > 90 minutes
- Checker also verifies recent success state for backup/public snapshot jobs.
- Emit structured status JSON to `/var/log/cveintel/ops_health_status.json`.

3. Notification routing
- Single destination channel for all alerts (webhook-first design: Slack/Discord compatible).
- Same channel used for VM power alerts and in-VM freshness alerts to avoid split visibility.

4. Operational safety
- Health checker runs via systemd timer (e.g., every 10–15 minutes).
- Debounce duplicate alerts to reduce noise (cooldown window).
- Keep all secrets/tokens externalized in `/etc/cve-intel.env`.

### Implementation plan (next in this phase)

- Create and install:
  - `cveintel-ops-health.service`
  - `cveintel-ops-health.timer`
  - `scripts/ops/ops_health_check.sh`
- Configure Azure Monitor + Action Group for VM deallocation events.
- Verify by forcing test conditions and confirming delivery to configured channel.

### Implemented (initial)

- Azure-side infra alerting:
  - Created Action Group: `cveintel-ops-ag` (email target configured).
  - Created Activity Log alert: `cveintel-vm-deallocate-alert` scoped to `CVE-server` for deallocate operations.
- VPS-side freshness checker:
  - Installed `cveintel-ops-health.service` + `cveintel-ops-health.timer` (15-minute cadence).
  - Installed `/usr/local/bin/cveintel-ops-health.sh`.
  - Status output now written to `/var/log/cveintel/ops_health_status.json`.
  - Added `scrape_active_state` handling so long-running active scrapes do not false-alert on stale completion timestamp.

### Current closure status (JSON-removal gate)

- Gate remains **open** until the currently timer-fired scrape run fully exits `inactive` with `Result=success`.
- Verified already:
  - Postgres-only paths are active (`Export complete (Postgres-only)` and `Loaded ... signatures from Postgres` in logs).
  - No recent `data/*.json` writes in the latest audit window (`find data -mmin -360` returned empty).

---

## 2026-07-24 — Scrape Stabilization + Telegram Alert Routing (In Progress)

### Why this step was needed

- `cveintel-scrape.service` was repeatedly failing after JSON-removal cutover due timeouts in `nvd_scraper` under full-run load.
- Observed failure signatures:
  - NVD window paging timeout (`Window 2 failed: ... context deadline exceeded`).
  - Final `nvd_intel` upsert timeout (`Postgres upsert failed: timeout: context deadline exceeded`).
- `cveintel-ops-health` alerts were not externally delivered because no alert destination env var was configured (`ALERT_WEBHOOK_URL not set`).

### Changes applied

1. `nvd_scraper.go` resilience hardening
- Added env-config helpers:
  - `NVD_UPSERT_TIMEOUT` (default `30m`).
  - `NVD_UPSERT_BATCH_SIZE` (default `2000`).
  - `NVD_HTTP_TIMEOUT` (default `2m`).
  - `NVD_HTTP_MAX_RETRIES` (default `3`).
- Changed `nvd_intel` persistence from one huge transaction to batched transactions with progress logging.
- Added robust retry/backoff behavior in NVD HTTP fetch path for transient network/read and 429/5xx errors.

2. Ops alert delivery upgrade
- Updated `scripts/ops/ops_health_check.sh`:
  - If `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` are set, send alerts via Telegram Bot API `sendMessage`.
  - Fallback to `ALERT_WEBHOOK_URL` if Telegram vars are absent.
  - If neither is set, emit a clear syslog message.

### Deployment status

- Patched `nvd_scraper.go` rebuilt and deployed on VPS (`/home/nixk2000/CVE-Intel/nvd_scraper`).
- Patched ops health script deployed to `/usr/local/bin/cveintel-ops-health.sh`.
- `cveintel-ops-health.timer` restarted.
- Manual scrape run started with patched binary; run is currently active and being observed for full completion.

### Pending verification before closure

- Wait for active scrape run to fully exit with `ActiveState=inactive` and `Result=success`.
- Confirm no recurrence of NVD paging timeout or final upsert timeout in this run.
- Confirm Telegram env vars are present in `/etc/cve-intel.env` and validate alert delivery with one triggered stale condition.

### 2026-07-24 follow-up: alert UX + Telegram command bot

- Upgraded `/usr/local/bin/cveintel-ops-health.sh` alert formatting:
  - Human-readable durations (`5h 7m`, `16h 29m`) instead of raw seconds.
  - Full per-service lines in every alert (scrape/news/backup/snapshot), not only failing checks.
  - Explicit scrape semantics while active (`freshness intentionally excluded`).
  - Added active-state ceiling (`SCRAPE_ACTIVE_MAX_SECONDS`, default 6h) so a permanently "activating" scrape still alerts.
  - Added optional test labeling via `OPS_HEALTH_TEST_MODE=true` (`🧪 TEST ALERT` prefix).
  - Scrape-related failures now include recent relevant scrape log excerpts (last 1-2 lines).

- Added read-only Telegram command bot service:
  - Script: `/usr/local/bin/cveintel-telegram-bot.py`
  - Unit: `/etc/systemd/system/cveintel-telegram-bot.service`
  - Polling model: Telegram `getUpdates` loop (no webhook/public endpoint).
  - Allowed chat enforcement: only `TELEGRAM_CHAT_ID` is served.
  - Commands implemented: `/status`, `/scrape`, `/backup`, `/help`.
  - No destructive operations; status/read-only responses only.

- Deployment verification:
  - `cveintel-telegram-bot.service` is active/running.
  - Forced test-mode alert executed from VPS code path; `ops_health_status.json` recorded `test_mode=true` and failed checks as expected.
  - Bot now logs command handling events to journald for response verification.

### 2026-07-24 follow-up: status polish

- Set bot VM env keys in `/etc/cve-intel.env`:
  - `AZ_RESOURCE_GROUP=CVE-Intel`
  - `AZ_VM_NAME=CVE-server`
- Identified root cause of occasional `/status` output `last success unknown ago`:
  - Telegram bot `last_epoch()` parser could receive journal output containing an extra boot-separator line and fail integer parsing.
  - Fixed by parsing the **last output line** explicitly before converting epoch.
- Deployed fixed bot script and restarted `cveintel-telegram-bot.service`.

### 2026-07-24 correction: deployed bot version mismatch resolved

- Observed `/status` still returning `last success unknown ago`.
- Root cause: VPS `/usr/local/bin/cveintel-telegram-bot.py` was still an older deployed version despite a prior restart.
- Action:
  - Re-copied script to VPS, force-installed to `/usr/local/bin/cveintel-telegram-bot.py`.
  - Verified checksum match with local source.
  - Confirmed deployed code now contains the `last_epoch()` splitlines-last-line parser and improved VM fallback messages.
  - Restarted `cveintel-telegram-bot.service`.

---

## 2026-07-24 — Scrape stale alert incident (post-upsert validation timeout)

### What happened

- `nvd_scraper` completed successfully (including batched `nvd_intel` upsert to 369,953 rows), but the scrape service still failed in the final `validate.go` step.
- Root cause: validator used a single 30-second context for all DB checks; after heavy run/postgres load, multiple validator queries timed out (`context deadline exceeded`), causing service exit-code failure.
- Because `scrape cycle complete` marker was never written, ops-health correctly alerted `Scrape: STALE`.

### Fixes applied

1. Validator timeout hardening
- `validate.go` now reads `VALIDATE_TIMEOUT_SECONDS` (default 180s) instead of fixed 30s.
- Deployed updated `validate.go` to VPS.
- Verified on VPS with env loaded: `Validation PASSED`.

2. Ops alert dedupe key stabilization
- In `ops_health_check.sh`, alert cooldown key now uses stable error codes (`scrape_stale`, `news_stale`, etc.) instead of dynamic human strings containing changing ages.
- This prevents duplicate Telegram alerts every 15 minutes when condition is unchanged.
- Deployed updated script to `/usr/local/bin/cveintel-ops-health.sh` and restarted timer/service.

### Recovery action

- Started a fresh manual scrape cycle at `2026-07-24T17:48:33Z`:
  - `systemctl start --no-block cveintel-scrape.service`
  - confirmed `ActiveState=activating` and new cycle logs.
- Waiting for terminal `inactive + Result=success` to clear stale condition and close the gate.

---

## 2026-07-27 — Operational Status Audit and Documentation Closure

### Why this entry

- Performed a full "current state" audit after several days of unattended operation.
- Verified timers/services, status files, and recent logs directly on VPS.

### Current runtime status (audit time: 2026-07-27 12:45 UTC)

- `cveintel-scrape.timer`, `cveintel-news.timer`, `cveintel-backup.timer`, `cveintel-public-snapshot.timer`, `cveintel-ops-health.timer`: **active**
- `cveintel-telegram-bot.service`: **active/running**
- `cveintel-duckdns.timer`: active; `duckdns_status.json` shows regular successful updates.

Status files:
- `ops_health_status.json`: `status=ok` (scrape active and within active ceiling, no current errors)
- `backup_status.json`: latest completed run `2026-07-27T02:31:00Z`, dump size `210,249,383` bytes, `lfs_required=true`
- `public_snapshot_status.json`: latest completed run `2026-07-26T03:01:07Z`, tag `snapshot-2026-07-26`

### Scrape pipeline status

- Verified successful full scrape cycle on `2026-07-27`:
  - `Postgres upsert complete for nvd_intel: 370397 rows`
  - `Validation PASSED`
  - `scrape cycle complete` logged at `2026-07-27T08:47:47Z`
- DB counts from that successful cycle summary:
  - `cve_repos rows: 17975`
  - `cve_repos distinct CVEs: 7954`
  - `nvd_intel rows: 370397`
  - `news_items rows: 380`

### Notes on long-running active scrape

- A later timer-fired scrape (started at `2026-07-27T12:00:01Z`) remained in-progress during the audit and showed retry lines in the large NVD window.
- This was treated as **active work**, not stale failure, because:
  - process was alive and consuming CPU (`./nvd_scraper`)
  - ops-health active-state exclusion + ceiling logic remained satisfied.

### Phase/gate status update

- JSON-removal migration gate is treated as **closed** based on successful post-fix timer-driven scrape completion with `Validation PASSED` and `scrape cycle complete` marker.
- Project operations moved from migration triage into normal run monitoring mode.

---

## 2026-07-28 — API/Frontend Performance and Documentation Sync (GitHub main)

### Why this entry

- Implemented and published follow-up performance and documentation fixes after post-migration review feedback.
- Primary objective was to reduce high-latency payload fan-out patterns while keeping API compatibility for existing consumers.

### Commits published to `main`

- `d1c785af` — `api: add pagination, caching, and intel summary endpoint`
- `96934091` — `dashboard: replace global fan-out search with paged api search`

### Code and API changes

1. FastAPI response + pagination improvements (`api/main.py`)
- Added optional pagination to:
  - `GET /api/cve/{year}` via `page` + `per_page`
  - `GET /api/intel/{year}` via `page` + `per_page`
- Added optional `cve_ids` filter to `GET /api/intel/{year}` for scoped intel retrieval.
- Added cache-control support in JSON response helper and applied route-level policy:
  - year/intel endpoints: `public, max-age=300`
  - news endpoint: `public, max-age=120`
  - search endpoint: `no-store`
- Added new endpoint:
  - `GET /api/intel-summary/{year}`
  - returns compact intel only for CVEs mapped in `cve_repos` for that year.

2. Frontend load-path optimization
- Updated `index.html` to use `/api/intel-summary/{year}` for landing-chart intel context instead of full `/api/intel/{year}` calls.
- Updated `dashboard.html` global search path:
  - removed all-years CVE/intel bulk fan-out fetch behavior.
  - switched to bounded, paginated `/api/search` calls.
  - added `AbortController` cancellation to prevent stale in-flight search requests during rapid input/filter changes.
  - preserved client-side sort/filter behavior on returned rows.

3. Documentation and repo metadata updates
- Added `LICENSE` (MIT).
- Updated `README.md` API surface with new endpoint and pagination/filter query notes.
- Updated `docs.html` language/examples to reflect Postgres + FastAPI runtime and paginated usage examples.

### Production verification snapshot

- GitHub verification:
  - Both commits are present on `origin/main`.
- Live host probe against `https://cve-intel.duckdns.org` (immediate post-push check):
  - `GET /api/cve/2026?page=1&per_page=50` -> `200`
  - `GET /api/search?q=openssl&page=1&per_page=10` -> `200`
  - `GET /api/intel-summary/2026` -> `404`
  - `GET /api/intel/2026` -> `200`, payload observed ~25 MB

### Interpretation / operational state

- Public repository (`main`) is updated.
- VPS runtime is likely still on an older deployment revision for API service:
  - missing `/api/intel-summary/{year}` route
  - cache-control headers from updated API code not yet observed on live responses.

### Pending action to fully close this phase

1. Deploy latest `main` to VPS API service and restart/reload FastAPI runtime.
2. Re-run live endpoint checks for:
  - route availability (`/api/intel-summary/{year}`)
  - response headers (`Cache-Control`) through Caddy proxy.
3. Capture post-deploy payload-size/waterfall evidence and append to this log.

### 2026-07-28 follow-up: GitHub Actions CI failure clarification and fix

- Observed GitHub Actions run failure on workflow `CI` after docs push.
- Warning present in run annotations:
  - Node.js 20 deprecation notice for `actions/checkout@v4` and `actions/setup-go@v5` (informational, non-fatal).
- Actual failure root cause:
  - `Validate dataset integrity` step executed `go run validate.go` without DB credentials.
  - `validate.go` now requires `DATABASE_URL` or `POSTGRES_*` env and exits with status 1 when absent.

Fix applied on `main`:
- Updated `.github/workflows/ci.yml` validation step to be DB-gated:
  - read `DATABASE_URL` from `secrets.DATABASE_URL`
  - skip step with explicit message when secret is not configured
  - execute `go run validate.go` only when DB secret is present.

### 2026-07-28 follow-up: Node runtime deprecation warning cleanup

- Continued CI hygiene after the failure fix by updating GitHub-hosted action versions in `.github/workflows/ci.yml`:
  - `actions/checkout` from `@v4` -> `@v7`
  - `actions/setup-go` from `@v5` -> `@v7`
  - `actions/setup-python` from `@v5` -> `@v7`
- Goal: remove Node 20 deprecation annotation noise from Actions runs and align workflow with current runner runtime.

### 2026-07-28 follow-up: CI smoke backend parity fix

- Remaining CI failure after DB-gating fix was in step `Run browser smoke tests`.
- Root cause:
  - smoke suite ran against `python -m http.server` static host.
  - frontend now depends on `/api/*` endpoints, so static-only host could not satisfy runtime fetch paths.
- Fix applied:
  - Added `scripts/ci/mock_api_server.py` (static file serving + lightweight deterministic `/api/*` mocks used by smoke suite).
  - Updated `.github/workflows/ci.yml` smoke step to start `mock_api_server.py` instead of raw static server.
  - Mock provides required routes for smoke checks: `/api/health`, `/api/cve/{year}`, `/api/intel/{year}`, `/api/intel-summary/{year}`, `/api/news`, `/api/search`.

Verification:
- GitHub Actions run `30345385404` on commit `b0ac54ef` completed `success`.
- `build` job step results:
  - `Build scrapers` -> success
  - `Validate dataset integrity (DB-gated)` -> success (skip-path behavior active without DB secret)
  - `Install Playwright` -> success
  - `Run browser smoke tests` -> success

### 2026-07-28 follow-up: operations runbook gap closure

- Identified documentation gap: API/web service unit discovery and restart path was not documented in a dedicated operations runbook.
- Added `OPERATIONS.md` with:
  - API service discovery commands (`systemctl list-units`, `ss -tlnp`, PID mapping)
  - deploy sequence (`fetch/log/pull`, API restart, journal checks)
  - post-deploy verification checks for `/api/intel-summary/*`, pagination/search endpoints, and response headers/payload sizing
  - rollback + evidence logging checklist.
- Added `OPERATIONS.md` to `README.md` documentation index.

2026-07-28 extension:
- Expanded `OPERATIONS.md` with operational hardening details:
  - 24-hour `journalctl` checks for scrape/news/backup/snapshot units
  - status-file quick-check commands under `/var/log/cveintel/*.json`
  - explicit "Common failure points" section (timeouts, rate volatility, auth drift, env drift, restart misses)
  - 6-step incident response pattern for consistent on-call handling.

### 2026-07-28 — VPS API deployment + live verification closure

Deployment context:
- VPS runtime was serving API from Docker container `cveintel-api` (image `cve-intel-vps-api`) via Caddy.
- Existing `~/CVE-Intel` checkout on VPS was intentionally dirty (ingestion outputs + local changes), so direct pull/deploy there was high risk.

Safe deploy path used:
1. Created clean deploy worktree from `origin/main`:
   - `/home/nixk2000/CVE-Intel-deploy` @ `ad6514c81`
2. Updated `~/cve-intel-vps/docker-compose.yml` API build context:
   - from `/home/nixk2000/CVE-Intel`
   - to `/home/nixk2000/CVE-Intel-deploy`
3. Rebuilt and restarted only API container:
   - `docker compose build api`
   - `docker compose up -d api`

Runtime verification:
- `docker ps` showed:
  - `cveintel-api` up and bound on `127.0.0.1:8000`
  - `cveintel-postgres` healthy
- `docker logs cveintel-api` confirmed clean startup and successful route hits.

Post-deploy live checks (from VPS):
- `GET /api/intel-summary/2026`:
  - `HTTP/2 200` (previously `404`)
  - `Cache-Control: public, max-age=300`
- `GET /api/intel/2026`:
  - `HTTP/2 200`
  - `Cache-Control: public, max-age=300`
- Payload sizes captured:
  - `/api/intel-summary/2026`: `1,021,703` bytes
  - `/api/intel/2026`: `25,467,039` bytes

Interpretation:
- API deployment is now live and serving new routes + cache headers through Caddy.
- Summary endpoint is materially smaller than full-year intel payload (~1.0 MB vs ~25.5 MB), validating intended optimization.

### 2026-07-28 — Runbook source-of-truth consolidation

- Found two runbooks in repo (`OPERATIONS.md` and `docs/OPERATIONS.md`) with divergent content.
- To eliminate drift risk, `docs/OPERATIONS.md` was converted to a pointer that links to root `OPERATIONS.md` as canonical source.
