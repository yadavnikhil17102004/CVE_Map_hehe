# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Autonomous threat intelligence aggregator. Discovers CVE exploit PoCs on GitHub, correlates with NVD/CISA KEV data, and serves everything as a zero-cost static dashboard via GitHub Pages. Updates every 6h (CVEs) and 1h (news) via GitHub Actions.

## Commands

```bash
# Local dev server (Python HTTP + auto-open browser)
./start.sh

# Build & run scrapers manually
go build cvemapping.go && ./cvemapping -github-token=$GITHUB_TOKEN
go build nvd_scraper.go && ./nvd_scraper -nvd-key=$NVD_API_KEY
go build news_scraper.go && ./news_scraper

# Rebuild Tailwind CSS (only needed when modifying styles)
npx tailwindcss -i input.css -o style.css --watch

# Run individual Go file
go run cvemapping.go -github-token=$GITHUB_TOKEN
```

GitHub Actions handles all production runs — no deploy step needed beyond pushing to main.

## Architecture

**Three independent Go scrapers → static JSON → GitHub Pages CDN → vanilla JS frontend**

```
GitHub API ──→ cvemapping.go ──→ data/{year}.json     (1999–2026)
NVD API ─────→ nvd_scraper.go ─→ data/nvd_intel_YYYY.json (canonical, compact 1-char keys)
                                   └→ data/nvd_intel.json      (generated compatibility artifact)
RSS Feeds ───→ news_scraper.go → data/news.json        (tiered, hourly)
                                         ↓
                              GitHub Pages (static CDN)
                                         ↓
              dashboard.html + news.html + index.html (vanilla JS, Chart.js)
```

**No database. No backend. No npm. Zero external Go dependencies (stdlib only).**

### Scraper Design Patterns

- **cvemapping.go**: Monthly chunking when GitHub search >1000 results. Deduplicates per CVE by highest star count. Exports minified JSON with `json.Marshal` (not `MarshalIndent`).
- **nvd_scraper.go**: Two-phase — Phase 1 fetches 180-day window; Phase 2 backfills missing CVEs from existing year JSONs. NIST primary → CNA secondary → v2 fallback for CVSS priority.
- **news_scraper.go**: 12 RSS feeds concurrently via `sync.WaitGroup`. Tier 1 (CISA/Rapid7) through Tier 5 (Reddit). Strips HTML, extracts images from enclosure/media tags.

### Rate Limit Handling

- GitHub: 2–3s sleep between requests, exponential backoff on 403, reads `Retry-After` header
- NVD: 6.5s sleep unauthenticated / 650ms with API key

### Frontend

- Vanilla JS, no frameworks. Chart.js via CDN for line/donut charts.
- Year selector updates `currentYear` state, re-renders table and charts.
- Search debounced 280ms, searches across all years simultaneously.
- Chart.js instances explicitly destroyed before recreation (prevent memory leaks).
- `nvd_intel_YYYY.json` (canonical) and generated `nvd_intel.json` share 1-char keys: `s`=score, `v`=severity, `d`=description, `c`=vector, `w`=cwe, `k`=kev_flag, `p`=publish_date

## Workflows

- `.github/workflows/scrape.yml` — every 6h: builds + runs cvemapping.go + nvd_scraper.go, commits JSON diffs
- `.github/workflows/news.yml` — every 1h: builds + runs news_scraper.go, commits only `data/news.json`

Separate workflows prevent race conditions between the 6h and 1h jobs.

## Required Secrets (GitHub Actions)

| Secret | Required | Notes |
|--------|----------|-------|
| `GITHUB_TOKEN` | Yes | Auto-provided by Actions; passed as `-github-token` flag |
| `NVD_API_KEY` | Optional | 10x higher rate limit (50 req/30s vs 5 req/30s) |

## Data Schema

**`data/{year}.json`**
```json
{ "year": 2026, "cves": [{ "cve_id": "CVE-2026-XXXX", "repositories": [{ "name", "url", "description", "stars", "language", "last_push" }] }] }
```

**`data/nvd_intel_YYYY.json`** — canonical per-year compact maps (1-char keys)
```json
{ "CVE-2026-XXXX": { "s": 9.8, "v": "CRITICAL", "d": "...", "c": "CVSS:3.1/AV:N/...", "w": "CWE-89", "k": true, "p": "2026-01-01" } }
```

**`data/nvd_intel.json`** — generated aggregate compatibility artifact (same schema)
```json
{ "CVE-2026-XXXX": { "s": 9.8, "v": "CRITICAL", "d": "...", "c": "CVSS:3.1/AV:N/...", "w": "CWE-89", "k": true, "p": "2026-01-01" } }
```

**`data/news.json`**
```json
{ "last_updated": "...", "articles": [{ "title", "link", "description", "pub_date", "source", "tier", "image_url" }] }
```

## Key Constraints

- Host is Intel MacBook Pro x86_64. No ARM-only tooling.
- Do not modify `style.css` manually — it's compiled Tailwind output.
- Adding new RSS sources: edit `news_scraper.go` tier map, assign tier 1–5 by source authority.
- Go module path: `github.com/yadavnikhil17102004/CVE_Map_hehe`
