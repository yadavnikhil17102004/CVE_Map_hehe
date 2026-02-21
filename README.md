# 🗺️ CVE Map (Hehe)

> _Continuous, automated aggregation of every GitHub CVE exploit Proof-of-Concept. Updated every 6 hours._

## ⚡ What is this?

A lightning-fast native Go engine that scrapes the GitHub API for documented CVE exploits across the internet and indexes them into static JSON datasets.

**Why?** Because manual exploit hunting during an engagement is slow, and speed is king.

## 🛠 Features

- **Automated Upstream Sync:** Powered by a custom, ultra-fast in-memory GitHub Actions pipeline that deterministically syncs vulnerability mappings into this timeline.
- **Zero-Bloat JSON Exports:** Clean, static datasets mapping CVE IDs directly to GitHub repositories.
- **Cross-Platform Go Binary:** Simple compilation, simple execution.

## 🚀 Installation

**Standard Go Install:**

```bash
go install github.com/yadavnikhil17102004/CVE_Map_hehe@latest
```

**Compile from Source:**

```bash
git clone --depth 1 https://github.com/yadavnikhil17102004/CVE_Map_hehe.git
cd CVE_Map_hehe
go install
```

## 💥 Usage

Feed the engine a specific CVE range to aggressively aggregate all associated repositories:

```bash
# Export all 2024 CVE PoCs to static JSON for website processing
echo '"CVE-2024-"' | cvemapping -github-token "YOUR_GITHUB_TOKEN" -page all -year 2024 -export-json

# Command Line Interface Options
Usage of cvemapping:
  -export-json
        Export data to JSON files instead of cloning (Highly Recommended)
  -github-token string
        GitHub API User Token for high-rate limit authentication
  -page string
        Page number to fetch, or 'all' (default "1")
  -year string
        Year to search for CVEs (e.g., 2024, 2020)
```

## 🌐 Threat Intelligence Dashboard

The engine automatically exports highly-minified, raw JSON datasets directly to the `web/data` structure. Instead of serving this yourself, **GitHub Pages natively hosts the entire platform**.

**View the Live Dashboard:**
👉 `https://yadavnikhil17102004.github.io/CVE_Map_hehe/`

### 📡 Public Open API (JSON)

Because the datasets are statically built and pushed via GitHub Actions, mapping data acts as a zero-cost API CDN. You can natively pull the raw intelligence into your own security tools.

**Endpoint Format:**

```bash
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/{YYYY}.json
```

**Example (Fetch 2024 intel):**

```bash
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/2024.json | jq '.cves[] | .cve_id'
```

_(The dashboard Javascript natively wraps the official US National Vulnerability Database API to pull CVSS metrics in real-time)._
