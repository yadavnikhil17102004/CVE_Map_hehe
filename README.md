<div align="center">
  <h1>🗺️  C V E &nbsp; M A P</h1>
  <p><b>Autonomous GitHub Exploit Intelligence — Live & Updated Every 6 Hours</b></p>
  <br>

[![Live Dashboard](https://img.shields.io/badge/Dashboard-LIVE-66FCF1?style=for-the-badge&logo=github)](https://yadavnikhil17102004.github.io/CVE_Map_hehe/)
[![Engine](https://img.shields.io/badge/Engine-Go_1.25-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![NVD](https://img.shields.io/badge/Intel-NVD_API_v2.0-red?style=for-the-badge)](https://nvd.nist.gov/)
[![Sync](https://img.shields.io/badge/Sync-Every_6_Hours-success?style=for-the-badge&logo=githubactions)](https://github.com/features/actions)

### 🌐 [→ Open the Live Dashboard](https://yadavnikhil17102004.github.io/CVE_Map_hehe/)

</div>

---

## What is CVE Map?

CVE Map is an automated threat intelligence aggregator that scrapes GitHub for real-world CVE exploit repositories, maps them to NVD vulnerability data, and serves everything as a live dashboard — no accounts, no API keys, no setup required.

Every **6 hours**, a Go engine automatically:

1. Searches GitHub for repositories documenting CVEs (PoCs, exploits, writeups)
2. Pulls CVSS scores, CWE IDs, and CISA KEV status from the NVD API
3. Commits the results as static JSON files that are instantly queryable

---

## Dashboard Features

| Feature                  | Description                                                              |
| ------------------------ | ------------------------------------------------------------------------ |
| **Year Timeline**        | Browse exploit data from 2015 through today                              |
| **Sortable Table**       | Click any column — CVE ID, Type, Activity, Stars — to sort asc/desc      |
| **Global Search**        | Searches across all years simultaneously                                 |
| **NVD Intel Panel**      | Click any CVE for full details: CVSS score, vector, CWE, CISA KEV status |
| **Exploit Trends Chart** | Monthly repo push activity timeline                                      |
| **Severity Donut**       | CRITICAL / HIGH / MEDIUM / UNSCORED distribution                         |
| **Live Activity Feed**   | Most recently pushed exploit repos in real-time                          |
| **🔴 CISA KEV Badge**    | Flags CVEs confirmed exploited in the wild                               |

---

## Public API (Free, No Key Required)

The scraped data is served as static JSON via GitHub Pages — use it in your own tools.

```bash
# All CVE exploit mappings for a given year
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/2025.json | jq '.cves[].cve_id'

# NVD intel for a specific CVE (score, severity, vector, CWE, CISA KEV)
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/nvd_intel.json | jq '."CVE-2025-55182"'
```

### Data Schema

**`data/{year}.json`**

```json
{
  "year": 2025,
  "cves": [
    {
      "cve_id": "CVE-2025-55182",
      "repositories": [
        {
          "full_name": "user/repo",
          "html_url": "https://github.com/user/repo",
          "description": "PoC exploit for CVE-2025-55182",
          "stargazers_count": 42,
          "pushed_at": "2025-12-10T18:30:00Z"
        }
      ]
    }
  ]
}
```

**`data/nvd_intel.json`**

```json
{
  "CVE-2025-55182": {
    "s": 10.0,
    "v": "CRITICAL",
    "d": "A pre-authentication RCE vulnerability in React Server Components...",
    "c": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "w": "CWE-502",
    "k": true,
    "r": "CNA",
    "p": "2025-12-03"
  }
}
```

| Key | Field           | Example               |
| --- | --------------- | --------------------- |
| `s` | CVSS Base Score | `10.0`                |
| `v` | Severity        | `CRITICAL`            |
| `d` | Description     | `"A pre-auth RCE..."` |
| `c` | CVSS Vector     | `"CVSS:3.1/AV:N/..."` |
| `w` | CWE ID          | `"CWE-502"`           |
| `k` | CISA KEV        | `true`                |
| `r` | Score Source    | `"NIST"` or `"CNA"`   |
| `p` | Published Date  | `"2025-12-03"`        |

---

## Architecture

```
GitHub Actions (every 6h)
├── cvemapping.go     → Searches GitHub API for CVE-tagged repos
│                       Handles >1000 results via monthly chunking
│                       Exports → data/{year}.json
│
└── nvd_scraper.go    → Phase 1: NVD 180-day modification window
                        Phase 2: Targeted backfill for unscored CVEs
                        Exports → data/nvd_intel.json

GitHub Pages serves all JSON as a zero-cost CDN
Dashboard (index.html) fetches JSON → renders UI client-side
No server. No database. No backend.
```

---

## Fork & Deploy Your Own

1. **Fork** this repository
2. **Enable GitHub Actions**: Settings → Actions → General → Allow all actions
3. **Add Secrets** (Settings → Secrets → Actions):
   - `SYNC_TOKEN` — GitHub Personal Access Token with `repo` scope
   - `NVD_API_KEY` — [Free from NVD](https://nvd.nist.gov/developers/request-an-api-key) (10x speed boost)
4. **Enable GitHub Pages**: Settings → Pages → Deploy from branch `main` at `/`
5. **Run the workflow** manually from the Actions tab — first run builds the full database

---

> _"Secure by design is nice, but secure by penetration testing is truth."_
