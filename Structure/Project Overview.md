# CVE Map Project Overview

> [!info] Purpose
> Autonomous threat-intelligence dashboard that maps real-world GitHub CVE exploit proof-of-concepts (PoCs) to NVD/CISA intelligence and serves it as a static website.

> [!summary] What it does
> Continuously correlates:
> - GitHub exploit/PoC repository activity
> - NVD CVSS/CWE metadata
> - CISA KEV exploitation status
> - Hourly cybersecurity news signals
> 
> No backend. No database. No paid infra. Everything is static JSON + GitHub Pages.

## 🔑 Key Features
- Global CVE/PoC search across years
- Dashboard filters for:
  - Type (PoC / Exploit / General)
  - Severity (Critical / High / Medium / Low / Unscored)
  - KEV status (All / KEV only / Exclude KEV)
  - EPSS band (High / Medium+ / Low / Unknown)
- NVD side panel with CVSS, vector, CWE, source, KEV badge, EPSS (when available)
- Year timeline + trend charts + live activity feed
- Responsive news interface with tier filtering + keyword search
- Optimized frontend loading via year-scoped NVD intel files (`nvd_intel_YYYY.json`)

## 🧩 Architecture

```text
GitHub Exploit Repos      NVD/CISA KEV         RSS Feeds
         |                    |                    |
         v                    v                    v
   +------------+      +--------------+      +------------+
   | cvemapping |      | nvd_scraper  |      | news_scraper|
   +------------+      +--------------+      +------------+
         \                  /                    /
          \                /                    /
           +-----------------------------------+
                       data/*.json
                           |
                           v
                  GitHub Pages (static CDN)
                    /        |         \
                   v         v          v
              dashboard   docs       news
```

## ⚙️ Components

### Scrapers (Go)
- **cvemapping.go**: Maps GitHub exploit/PoC repos to CVEs → outputs `data/YYYY.json`
- **nvd_scraper.go**: Enriches with NVD/CISA data → outputs `data/nvd_intel_YYYY.json` & `data/nvd_intel.json`
- **news_scraper.go**: Curates hourly infosec news → outputs `data/news.json`

### Frontend (Static)
- `index.html`: Main dashboard with filters, tables, charts
- `docs.html`: Documentation and help
- `news.html`: News feed interface
- Assets: CSS, icons, Tailwind config

### Data (JSON in `data/` directory)
- `YYYY.json`: CVE → GitHub repo mapping for a specific year
- `nvd_intel_YYYY.json`: Year‑scoped NVD intel (frontend‑optimized)
- `nvd_intel.json`: Full NVD intel (backward compatibility)
- `news.json`: Curated news articles

### Automation (GitHub Actions)
- **scrape.yml** (every 6h): Runs `cvemapping` + `nvd_scraper`, updates `data/` JSON
- **news.yml** (hourly): Runs `news_scraper`, updates only `news.json`
- Separated workflows prevent data races

## 🚀 Local Development

### Prerequisites
- Go 1.25+
- Python 3 (optional, for tooling)
- Git

### Quick Start
```bash
./start.sh   # Serves at http://localhost:8000
```

### Manual Scraper Runs
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

### Build Check
```bash
go build cvemapping.go && go build nvd_scraper.go && go build news_scraper.go
```

## 📦 Deployment
- **Host**: GitHub Pages (static site)
- **CI/CD**: GitHub Actions push updated `data/` JSON directly to the publishing branch
- **No server**: 100% static — zero backend, zero database

## 👥 Intended Users
- Defensive security researchers
- Teams prioritizing patching (using KEV/EPSS)
- Cybersecurity students & educators
- Open‑source contributors improving PoC‑to‑CVE mapping

## ⚠️ Ethics & Disclaimer
> [!warning] Ethical Use
> This project is for **defensive threat intelligence, prioritization, and security research only**.
> **Do not use** for unauthorized exploitation, illegal access, or offensive security operations.

## 📚 Related Documents (Obsidian Links)
- [[README.md]] – Detailed quick start and feature list
- [[ROADMAP.md]] – Planned enhancements
- [[CONTRIBUTING.md]] – Contributor guidelines
- [[docs/operations/2026-08-14-stability-and-performance-log.md]] – Operational notes
- [[docs/operations/workflow-triage-runbook.md]] – Incident‑response runbook

## 🏷️ Tags
`#project-overview #threat-intel #cve #dashboard #static-site #go #github-pages`
