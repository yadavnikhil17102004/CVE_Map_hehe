# Data Flow

> [!info] Purpose
> Describes how data travels from raw sources (GitHub, NVD, RSS) to the static website served to users.

## 🔄 Overview
```text
External Sources
   │
   ▼
+----------------+   +----------------+   +----------------+
| GitHub API     |   | NVD API        |   | RSS Feeds    |
+----------------+   +----------------+   +----------------+
   │ cvemapping    │ nvd_scraper    │ news_scraper
   ▼               ▼               ▼
+----------------+   +----------------+   +----------------+
| data/YYYY.json │   | data/nvd_intel_YYYY.json │ data/news.json │
| (CVE → repos)   │   | (per‑year NVD intel)    │ (news feed)    |
+----------------+   +----------------+   +----------------+
   │               │                 │
   │               ▼                 │
   │        +----------------+       │
   │        | data/nvd_intel │       │
   │        | (aggregate)    │       │
   │        +----------------+       │
   │               │                 │
   └───────►───────┴───────►─────────┘
                   ▼
           +-------------------+
           | Frontend (JS)    |
           | - Loads per‑year | 
           |   NVD intel +    |
           |   yearly mapping |
           │ - Joins data      |
           │ - Applies filters |
           │ - Renders UI      |
           +-------------------+
                   │
                   ▼
           +-------------------+
           | Static Site       |
           | (GitHub Pages)    |
           +-------------------+
```

## 📥 Ingestion Steps
1. **GitHub → cvemapping**
   - Tool: `cvemapping.go`
   - Output: `data/YYYY.json` (one file per year, contains list of CVE objects with array of matching GitHub repos).
2. **NVD → nvd_scraper**
   - Tool: `nvd_scraper.go`
   - Inputs: all `data/YYYY.json` files (to know which CVEs to enrich).
   - Outputs:
     - `data/nvd_intel_YYYY.json` – enriched intel for that specific year (map CVE→details).
     - `data/nvd_intel.json` – merged intel for all years.
3. **RSS → news_scraper**
   - Tool: `news_scraper.go`
   - Output: `data/news.json` – array of news article objects.

## 🗄️ Storage
- All JSON files live in the `data/` directory at the repo root.
- Files are **committed** to the repository by GitHub Actions workflows (see Automation).
- The frontend fetches these files directly from GitHub Pages (raw.githubusercontent.com or the GitHub Pages domain).

## 🖥️ Consumption (Frontend)
- **Dashboard (`index.html`)**:
  - Determines year (from URL or default).
  - Loads `data/nvd_intel_YYYY.json` (fast, year‑scoped).
  - Loads `data/YYYY.json` (CVE‑to‑repos mapping).
  - Joins on CVE ID to build table rows.
  - Applies client‑side filters.
- **News page (`news.html`)**:
  - Loads `data/news.json` once and renders list.
- **Docs page** is static; no data fetch.

## ⏱️ Frequency
- **cvemapping + nvd_scraper**: every 6 hours (GitHub Actions `scrape.yml`).
- **news_scraper**: hourly (GitHub Actions `news.yml`).
- Frontend updates automatically when the underlying JSON changes (no server‑side caching; relies on HTTP cache headers; GitHub Pages serves with appropriate Cache‑Control).

## 📂 Related Files
- **Scrapers:** `cvemapping.go`, `nvd_scraper.go`, `news_scraper.go`
- **Workflows:** `.github/workflows/scrape.yml`, `.github/workflows/news.yml`
- **Data outputs:** `data/*.json`
- **Frontend:** `index.html`, `news.html`, `docs.html`

## 🏷️ Tags
`#data-flow #pipeline #github #nvd #rss #json #frontend`
