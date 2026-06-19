# CVE Map

Autonomous threat-intelligence dashboard that maps real-world GitHub CVE exploit PoCs to NVD/CISA intelligence and serves it as a static website.

Live site:
- Dashboard: https://yadavnikhil17102004.github.io/CVE_Map_hehe/
- News feed: https://yadavnikhil17102004.github.io/CVE_Map_hehe/news.html
- Docs: https://yadavnikhil17102004.github.io/CVE_Map_hehe/docs.html

## Why this exists

Most CVE feeds tell you what is vulnerable. They do not tell you what already has public exploit activity.

CVE Map closes that gap by continuously collecting:
- GitHub exploit/PoC repository activity
- NVD CVSS/CWE metadata
- CISA KEV exploitation status
- Hourly cybersecurity news signals

No backend. No database. No paid infra. Everything is static JSON + GitHub Pages.

## Key features

- Global CVE/PoC search across years
- Dashboard filters for:
  - Type (PoC / Exploit / General)
  - Severity (Critical / High / Medium / Low / Unscored)
  - KEV status (All / KEV only / Exclude KEV)
- NVD side panel with CVSS, vector, CWE, source, KEV badge, EPSS (when available)
- Year timeline + trend charts + live activity feed
- Responsive news interface with tier filtering + keyword search
- Optimized frontend loading via year-scoped NVD intel files (`nvd_intel_YYYY.json`)

## Quick start (local)

Requirements:
- Go 1.25+
- Python 3
- Optional: `NVD_API_KEY`, `SYNC_TOKEN`

Run local site:

```bash
./start.sh
# serves at http://localhost:8000
```

Run scrapers manually:

```bash
# CVE GitHub mapping
go build cvemapping.go
./cvemapping -github-token="$SYNC_TOKEN"

# NVD/CISA enrichment
go build nvd_scraper.go
./nvd_scraper -nvd-key="$NVD_API_KEY"

# Cybersecurity news feed
go build news_scraper.go
./news_scraper
```

Build sanity check:

```bash
go build cvemapping.go && go build nvd_scraper.go && go build news_scraper.go
```

## Data endpoints

Base URL:
`https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/`

Core files:
- `YYYY.json` — CVE ↔ GitHub repo mappings for that year
- `nvd_intel_YYYY.json` — year-scoped compact NVD intel (frontend-optimized)
- `nvd_intel.json` — aggregate intel map (backward compatibility)
- `news.json` — hourly curated news feed

Example usage:

```bash
# CVEs for a year
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/2026.json | jq '.cves[0]'

# Year-scoped NVD intel
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/nvd_intel_2026.json | jq 'to_entries[0]'

# News feed
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/news.json | jq '.articles[:3]'
```

## Data schema

`data/{year}.json`

```json
{
  "year": 2026,
  "cves": [
    {
      "cve_id": "CVE-2026-XXXX",
      "repositories": [
        {
          "full_name": "owner/repo",
          "html_url": "https://github.com/owner/repo",
          "description": "PoC details",
          "stargazers_count": 42,
          "language": "Python",
          "pushed_at": "2026-01-01T00:00:00Z"
        }
      ]
    }
  ]
}
```

`data/nvd_intel_YYYY.json` and `data/nvd_intel.json` (compact keys)

```json
{
  "CVE-2026-XXXX": {
    "s": 9.8,
    "v": "CRITICAL",
    "d": "Description",
    "c": "CVSS:3.1/...",
    "w": "CWE-79",
    "k": true,
    "r": "NIST",
    "p": "2026-01-01",
    "e": 0.42
  }
}
```

Key map:
- `s` score
- `v` severity
- `d` description
- `c` CVSS vector
- `w` CWE
- `k` KEV flag
- `r` score source
- `p` publish date
- `e` EPSS probability (optional)

## Architecture

Three independent Go scrapers produce static JSON consumed by vanilla JS pages.

```text
GitHub API  --> cvemapping.go --> data/YYYY.json
NVD API     --> nvd_scraper.go --> data/nvd_intel*.json
RSS feeds   --> news_scraper.go --> data/news.json

GitHub Pages serves static assets
index.html / dashboard.html / news.html / docs.html render client-side
```

Design constraints:
- Static hosting only (GitHub Pages)
- No backend runtime
- No external Go deps (stdlib-only scrapers)

## Automation (GitHub Actions)

- `.github/workflows/scrape.yml`
  - Runs every 6 hours
  - Builds + runs `cvemapping.go` and `nvd_scraper.go`
  - Commits updated `data/` JSON

- `.github/workflows/news.yml`
  - Runs hourly
  - Builds + runs `news_scraper.go`
  - Commits only `data/news.json`

Separated workflows reduce cross-job data races.

## Required secrets

Set in: `Settings -> Secrets and variables -> Actions`

- `SYNC_TOKEN` (required): GitHub token used by scraper workflow for authenticated API access
- `NVD_API_KEY` (recommended): faster NVD throughput and fewer rate-limit stalls

## Frontend performance notes

Recent optimization:
- `index.html` and `docs.html` fetch year-scoped intel files instead of loading the monolithic `nvd_intel.json` upfront.

Result:
- lower initial payload
- faster first render for dashboard analytics

## Troubleshooting

- Empty/slow CVE updates:
  - verify `SYNC_TOKEN`
  - check GitHub API rate limits
- Sparse NVD enrichments:
  - add/validate `NVD_API_KEY`
  - NVD outages can delay fields temporarily
- Charts not rendering:
  - verify `data/*.json` exists and is valid JSON
  - open browser devtools console for fetch errors

## Ethics and intended use

This project is for defensive threat intelligence, prioritization, and security research.
Do not use it for unauthorized exploitation or illegal access.
