# CVE-Intel Remediation Plan

> **Workflow:** For each step → **Understand** (goal + approach) → **Implement** → **Test** → **Validate** (CI/local gates) → **Mark done** → next step.  
> Do not start Step N+1 until Step N passes its test gate.

**Overall goal:** Close security, reliability, and deploy-size gaps from the Aug 2026 audit without breaking the live static dashboard.

**Execution order:** P0 security first, then reliability, then perf/maintainability.

**Parallel track:** [Upstream normalization (GCTI / Elasticsearch feed)](docs/plans/2026-08-27-upstream-normalization.md) — **U0 (P0 truncation fix) code is implemented**; rescrape pending for clean `data/`.

---

## How we work each step

```text
1. Read step block (Goal, Approach, Test)
2. Implement only that step's scope
3. Run step Test (manual + automated)
4. Run global sanity: go build, go run validate.go, local server smoke
5. Commit (when you choose) and move on
```

**Global sanity commands** (run after every step):

```bash
go build cvemapping.go && go build nvd_scraper.go && go build news_scraper.go && go build validate.go
go run validate.go
./start.sh   # then spot-check dashboard + news in browser
```

---

## Step 1 — Frontend XSS hardening

### Goal
Prevent script injection when rendering RSS news, NVD descriptions, and GitHub repo metadata via `innerHTML`.

### What we're doing
Today `index.html`, `dashboard.html`, and `news.html` interpolate untrusted strings (`article.title`, `article.link`, `article.image_url`, `intel.d`, `r.description`, etc.) directly into HTML. A compromised RSS entry or malicious repo description could execute JS in visitors' browsers.

### How we'll do it
1. Add a shared `escapeHtml(str)` helper (and `safeUrl(url)` allowing only `http:` / `https:`) in a small `assets/security.js` **or** duplicate minimal helpers at the top of each HTML file if we want zero new HTTP requests.
2. Replace every user/data-driven `innerHTML` interpolation with escaped values.
3. For attributes (`href`, `style` background URLs), escape + validate scheme; reject `javascript:`, `data:`, etc.
4. Prefer `textContent` for simple text nodes where we're rebuilding DOM manually (optional follow-up within same step).

**Files:** `index.html`, `dashboard.html`, `news.html`, optionally `assets/security.js`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Unit (manual)** | Inject payload in local `data/news.json`: `"title": "<img src=x onerror=alert(1)>"` | Page renders literal text; no alert; DevTools shows escaped entities (`&lt;img...`) |
| **Unit (manual)** | Payload in `description` and `link`: `"javascript:alert(1)"` | Link is stripped or rendered inert (no navigation to JS URL) |
| **Unit (manual)** | NVD panel: temporarily set a CVE `d` field to `<script>alert(1)</script>` in `data/nvd_intel_2026.json` | Description shows as text, script does not run |
| **Regression** | `python3 scripts/ci/issue-6-smoke.py http://127.0.0.1:8000` | All smoke checks pass |
| **Regression** | Browse dashboard search, filters, NVD side panel, news tier filter | No console errors |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. `escapeHtml()` helper (recommended)** | Tiny, no dependency, fits static site | Must apply consistently everywhere |
| **B. DOMPurify via CDN** | Battle-tested HTML sanitization | Extra dependency, CSP complexity, bundle size |
| **C. Build DOM with `createElement` + `textContent` only** | Safest | Larger refactor of template strings |

**Recommendation:** A now; consider B only if we need rich HTML in descriptions later.

---

## Step 2 — Pin Chart.js with Subresource Integrity (SRI)

### Goal
Eliminate supply-chain risk from unpinned `cdn.jsdelivr.net/npm/chart.js`.

### What we're doing
Chart.js is loaded without version pin or integrity hash. A CDN compromise could inject arbitrary JS on every page view.

### How we'll do it
1. Pick a fixed version (e.g. `4.4.1`).
2. Update script tags in `index.html`, `dashboard.html`, `docs.html` (any file loading Chart.js).
3. Add `integrity` + `crossorigin="anonymous"` attributes.
4. **Alternative path:** vendor `chart.umd.min.js` into repo (see Alternatives).

**Files:** `index.html`, `dashboard.html`, `docs.html` (grep for `chart.js`)

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Manual** | Load `index.html` and `dashboard.html` | Charts render (landing chart, severity donut, trend chart) |
| **Manual** | DevTools → Network → chart.js | 200 OK; URL matches pinned version |
| **Manual** | Tamper `integrity` hash intentionally | Browser blocks script (integrity error in console) — revert after |
| **Regression** | Smoke script | Pass |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. CDN + SRI pin (recommended)** | Small diff, cacheable | Still third-party network dependency |
| **B. Vendor file in repo** | No runtime CDN dependency | Must update manually; +~200KB in repo |
| **C. Remove Chart.js** | Zero supply chain | Lose charts; bad UX tradeoff |

---

## Step 3 — Trim GitHub Pages deploy artifact

### Goal
Stop deploying the entire 213MB repo (including 100MB `nvd_intel.json` monolith and Go sources) to GitHub Pages.

### What we're doing
`pages.yml` uploads `.` as the artifact. Visitors only need HTML, CSS, favicon, and `data/` JSON the frontend actually fetches.

### How we'll do it
1. Add a `scripts/build-pages.sh` (or CI step) that copies into `site/`:
   - `*.html`, `style.css`, `favicon.svg`, `input.css` (if needed)
   - `data/YYYY.json`, `data/nvd_intel_YYYY.json`, `data/news.json`
   - **Exclude** `data/nvd_intel.json` unless docs/API explicitly link to it (grep first).
2. Update `.github/workflows/pages.yml` to `path: site`.
3. Document which JSON files are public API surface in README.

**Files:** `.github/workflows/pages.yml`, new `scripts/build-pages.sh`, maybe `.gitignore` entry for `site/`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Build** | Run `scripts/build-pages.sh` locally | `site/` created; size ≪ 213MB |
| **Manual** | `cd site && python3 -m http.server 8000` | Dashboard, news, docs load; year intel fetches work |
| **Manual** | Confirm `site/data/nvd_intel.json` absent (if excluded) | Dashboard still works via year-scoped files |
| **CI** | Pages workflow on PR/push | Deploy succeeds; live URL loads |
| **Grep** | `grep -r nvd_intel.json *.html` | No required fetch to monolith (or only docs with fallback) |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. Staged `site/` artifact (recommended)** | Clean separation; fast deploys | Extra build script |
| **B. Keep monolith in deploy but remove from git** | Smaller git clone | Still fat deploy unless excluded |
| **C. Git LFS for large JSON** | Helps git | Doesn't fix Pages payload; adds cost/complexity |

**Also consider:** Stop committing `data/nvd_intel.json` to git (generate in scrape workflow only for archival). **Separate sub-step** after Step 3 validates deploy trim.

---

## Step 4 — Cap `nvdGet` retry loop (Go)

### Goal
Prevent unbounded recursion / hang when NVD returns sustained 403 rate limits.

### What we're doing
`nvd_scraper.go` recursively calls `nvdGet` on 403 with no max attempts.

### How we'll do it
1. Replace recursion with a `for` loop, `maxRetries := 3`.
2. Log each retry with attempt count.
3. Return error after exhaustion so scrape workflow fails visibly (not silent partial data).

**Files:** `nvd_scraper.go`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Unit** | Add `nvd_scraper_test.go` with httptest server returning 403 | Function errors after 3 attempts; no stack overflow |
| **Unit** | httptest returning 200 on 2nd attempt | Succeeds |
| **Integration** | `go run nvd_scraper.go` with valid `NVD_API_KEY` | Completes; intel files updated |
| **Regression** | `go run validate.go` | Pass |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. Loop + max 3 (recommended)** | Simple, matches `cvemapping` pattern | May fail run on long NVD outage |
| **B. Exponential backoff + higher cap** | More resilient | Longer workflow runtime |
| **C. Skip CVE on failure, continue** | Never blocks whole run | Silent data gaps |

---

## Step 5 — Data freshness guard in CI

### Goal
Detect stale `news.json` or current-year CVE data before it hits production silently.

### What we're doing
Scheduled workflows can fail without anyone noticing until users complain. Add staleness checks to `validate.go` or a new `validate_staleness.go`.

### How we'll do it
1. Parse `news.json` → `last_updated`; fail if older than **12 hours**.
2. Parse `data/YYYY.json` for current year; check file mtime or embed `scraped_at` field (if we add one later).
3. Env bypass: `ALLOW_STALE_DATA=true` for emergency CI green (mirror EPSS bypass pattern).
4. Wire into `ci.yml` after `go run validate.go`.

**Files:** `validate.go` (extend) or `validate_staleness.go`, `.github/workflows/ci.yml`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Unit** | Set `news.json` `last_updated` to 2 days ago | `go run validate.go` exits 1 with clear message |
| **Unit** | Fresh timestamps | Exits 0 |
| **Unit** | `ALLOW_STALE_DATA=true` with stale file | Warns but passes |
| **CI** | Push to branch | CI runs staleness check |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. Extend `validate.go` (recommended)** | One entrypoint | File grows |
| **B. Separate workflow cron** | Doesn't block PRs on old fork data | Doesn't gate merges |
| **C. GitHub Actions workflow status badge only** | Zero code | Reactive, not preventive |

---

## Step 6 — Incremental EPSS fetch

### Goal
Reduce scrape runtime and FIRST.org load by fetching EPSS only for new/changed CVEs.

### What we're doing
Phase 3 fetches EPSS for every key in `nvd_intel.json` each run. Dictionary is large and growing.

### How we'll do it
1. Track `epss_updated_at` per CVE in intel struct **or** sidecar `data/epss_cache.json`.
2. On run: compute `needsEPSS` = CVEs where EPSS missing OR intel record updated since last EPSS fetch.
3. Merge results; skip full-dictionary pull.
4. Keep `ALLOW_EMPTY_EPSS` guard for zero-result safety.

**Files:** `nvd_scraper.go`, possibly `data/` schema docs

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Unit** | Test `needsEPSS` logic with mock dict | Only changed IDs selected |
| **Integration** | Run scraper twice back-to-back | Second run EPSS phase completes faster; log shows small batch count |
| **Regression** | `go run validate.go` | EPSS coverage still ≥ 90% |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. Sidecar cache file (recommended)** | No change to compact intel keys | Extra file to manage |
| **B. New field `eu` (epss updated) in CVEIntel** | Self-contained | Bloats every record |
| **C. Weekly full EPSS refresh + incremental daily** | Balance | More scheduling logic |

---

## Step 7 — Widen CVE scrape window

### Goal
Keep historical year files from going stale (stars, new repos).

### What we're doing
`scrape.yml` only runs `cvemapping` for current year and last year.

### How we'll do it
1. Loop years: `[current, current-1, current-2]` (configurable via env `SCRAPE_YEAR_DEPTH=3`).
2. Stagger with existing sleep logic to respect GitHub limits.
3. Document token rate-limit expectations in runbook.

**Files:** `.github/workflows/scrape.yml`, `docs/operations/workflow-triage-runbook.md`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Manual dispatch** | `workflow_dispatch` scrape | Logs show 3 years processed |
| **Data** | Compare `data/2024.json` `updated_at` / repo counts before vs after | Changes reflect new activity |
| **Regression** | Workflow completes within GitHub job timeout | No timeout failure |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. Rolling 3-year window (recommended)** | Good freshness/cost balance | Longer workflow |
| **B. Weekly full historical rescan** | Complete | Very slow; rate limits |
| **C. Keep 2-year window** | No change | Audit finding remains |

---

## Step 8 — Filter `OTHER-YYYY` pseudo-CVEs from UI

### Goal
Stop `OTHER-2026`-style buckets from polluting search results and stats.

### What we're doing
`cvemapping` exports repos without CVE regex match into `OTHER-{year}` entries. Dashboard treats them like CVEs.

### How we'll do it
1. **Frontend (quick):** Filter `cve_id` matching `/^OTHER-\d{4}$/` in dashboard load/search/stats.
2. **Data (optional later):** Move to `data/unmapped_YYYY.json` in scraper.

**Files:** `dashboard.html`, optionally `cvemapping.go`, `docs.html`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Manual** | Search dashboard for `OTHER` | No rows (or dedicated "unmapped" section if we add one) |
| **Manual** | Stats cards | Counts exclude OTHER entries |
| **Regression** | Smoke script | Pass |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. Frontend filter (recommended first)** | Fast, no data migration | Data file still contains OTHER |
| **B. Scraper outputs separate file** | Clean data model | Requires migration + docs update |
| **C. Drop unmapped repos entirely** | Simplest JSON | Lose visibility into non-CVE repos |

---

## Step 9 — Go unit tests (core scraper logic)

### Goal
Lock in behavior for intel extraction, CVE collection, and HTML cleaning before future refactors.

### What we're doing
Zero `*_test.go` files today. Add focused table-driven tests.

### How we'll do it
1. `nvd_scraper_test.go`: `extractIntel`, `extractProducts`, `collectMissingCVEs`
2. `news_scraper_test.go`: `cleanHTML`, `parseTime`
3. `cvemapping_test.go`: `uniqueStrings`, `deduplicateRepositories`, `repoAgeDays`
4. Wire `go test ./...` into `ci.yml` (after extracting shared code if needed — may use same-package tests in `package main` files).

**Files:** `*_test.go`, `.github/workflows/ci.yml`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Automated** | `go test ./...` | All pass |
| **CI** | PR to main | Test job green |
| **Coverage spot-check** | `go test -cover` | Critical functions covered |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. Tests in `package main` (recommended)** | Minimal refactor | Can't import from other packages easily |
| **B. Refactor to `internal/nvd`, `internal/cvemap`** | Idiomatic Go | Large diff; defer until after P0 |

---

## Step 10 — Make browser smoke tests blocking

### Goal
Catch frontend regressions before merge.

### What we're doing
`ci.yml` has `continue-on-error: true` on Playwright smoke (per ROADMAP).

### How we'll do it
1. Confirm 3+ consecutive green smoke runs on main (or run locally 10x).
2. Remove `continue-on-error: true`.
3. Optionally add XSS payload check to `issue-6-smoke.py` after Step 1.

**Files:** `.github/workflows/ci.yml`, `scripts/ci/issue-6-smoke.py`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **CI** | Push PR | Smoke failure fails the job |
| **CI** | Green main branch | Full CI pass including smoke |

---

## Step 11 — Soften `validate.go` KEV assertion

### Goal
Avoid false CI failures when KEV count is temporarily zero due to upstream issues.

### What we're doing
`validate.go` hard-fails if `kevCount == 0`.

### How we'll do it
1. Change to **warning** unless count drops >50% vs previous run (store `data/.validate-baseline.json` in CI artifact or compare to committed baseline).
2. Keep hard fail for `requiredMissing` and EPSS coverage.

**Files:** `validate.go`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Unit** | Mock intel with `k: false` everywhere | Warns, does not exit 1 |
| **Unit** | Intel missing `s,v,d` | Still exits 1 |

---

## Step 12 — Repo hygiene (batch)

### Goal
Reduce confusion and improve dependency hygiene.

### What we're doing
- Module name `CVE_Map_hehe` ≠ repo `CVE-Intel`
- Stale `web/data/` referenced in scrape workflow
- No Dependabot
- `git config --global` in scrape workflow

### How we'll do it
1. Rename `go.mod` module to `github.com/yadavnikhil17102004/CVE-Intel` (no import paths to update if stdlib-only).
2. Remove `web/data/` from scrape `git add` or delete dead mirror.
3. Add `.github/dependabot.yml` for Actions.
4. Use `git config --local` in workflows.

**Files:** `go.mod`, `.github/workflows/scrape.yml`, `.github/dependabot.yml`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Build** | `go build` all scrapers | Pass |
| **CI** | Full pipeline | Pass |
| **Manual** | Dependabot opens Action update PR | Visible within 1 week |

---

## Step 13 — Document `SYNC_TOKEN` hardening (ops)

### Goal
Reduce blast radius of compromised PAT (process + docs; not fully automatable).

### What we're doing
Scrape uses `secrets.SYNC_TOKEN` with broad `contents: write`.

### How we'll do it
1. Document migration to fine-grained PAT (repo-only, metadata + contents read; use `GITHUB_TOKEN` for push if permissions allow).
2. Evaluate: push via `GITHUB_TOKEN` with `permissions: contents: write` on job instead of external PAT for git push.
3. Keep PAT only for GitHub **Search API** rate limits if required.

**Files:** `README.md`, `CONTRIBUTING.md`, `.github/workflows/scrape.yml`

### Test
| Type | Test | Pass criteria |
|------|------|---------------|
| **Manual** | Scrape `workflow_dispatch` with new token setup | CVE + NVD data updates land on main |
| **Security** | Token scopes in GitHub UI | Minimum required scopes only |

### Alternatives
| Option | Pros | Cons |
|--------|------|------|
| **A. Fine-grained PAT for API + GITHUB_TOKEN for push (recommended)** | Least privilege | Two credential types |
| **B. Single fine-grained PAT** | Simple | Still one secret to leak |
| **C. GitHub App** | Best for automation | Heavier setup |

---

## Execution checklist

| Step | Priority | Est. effort | Status |
|------|----------|-------------|--------|
| 1. XSS hardening | P0 | 2–3h | ⬜ |
| 2. Chart.js SRI | P0 | 30m | ⬜ |
| 3. Pages artifact trim | P1 | 1–2h | ⬜ |
| 4. nvdGet retry cap | P1 | 45m | ⬜ |
| 5. Staleness guard | P1 | 1h | ⬜ |
| 6. Incremental EPSS | P2 | 2–3h | ⬜ |
| 7. Widen scrape window | P2 | 30m | ⬜ |
| 8. Filter OTHER-* | P2 | 45m | ⬜ |
| 9. Go unit tests | P2 | 3–4h | ⬜ |
| 10. Blocking smoke CI | P1 | 15m | ⬜ |
| 11. Soft KEV validate | P3 | 45m | ⬜ |
| 12. Repo hygiene | P3 | 1h | ⬜ |
| 13. Token docs/hardening | P1 (ops) | 1h | ⬜ |

### Upstream normalization (GCTI feed) — see [docs/plans/2026-08-27-upstream-normalization.md](docs/plans/2026-08-27-upstream-normalization.md)

| Step | Priority | Status |
|------|----------|--------|
| U0. CVE id truncation fix | P0 | ✅ code |
| U1. `inferred_cve_ids` on repos | P1 | ✅ code |
| U2. NVD `m` (last_modified) | P1 | ✅ code |
| U3. CI validation hardening | P2 | ⬜ |
| U4. OTHER bucket docs | P2 | ⬜ |
| U5. `exploits_{year}.json` | P3 | ⬜ |

---

## Additional ideas (not in main sequence)

These came up in audit but are **deferred** unless you want them pulled forward:

1. **CSP meta tag** on all HTML pages — defense-in-depth after XSS fix; may break inline scripts/styles (needs nonce or hash policy).
2. **Remove `cloneRepo` code path** from `cvemapping.go` — dead in CI; reduces attack surface if someone runs tool wrong.
3. **Mobile nav handler** in `index.html` — UX fix, unrelated to security.
4. **Compress JSON** (`Content-Encoding`) — GitHub Pages doesn't gzip JSON at edge by default; artifact trim matters more.
5. **Separate public API** — publish trimmed JSON via GitHub Releases for consumers who need `nvd_intel.json` bulk dump.

---

## When we start implementing

Reply with **"Start Step 1"** (or any step number). For that step I will:

1. Restate goal + approach in short form  
2. Implement the fix  
3. Run the step's tests + global sanity  
4. Report pass/fail before moving on  

**Suggested start:** Step 1 (XSS) — highest user impact, no infra changes.
