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

## 🌐 Dataset Web Viewer

This engine automatically dumps CVE datasets into the `data/` directory. These can be served immediately via the included static renderer:

1. Generate JSON data via the `-export-json` flag.
2. Move JSON files into `web/data/`.
3. Serve the `web/` directory using any standard static HTTP server.
4. Profit.
