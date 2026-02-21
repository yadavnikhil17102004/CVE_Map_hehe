<div align="center">
  <h1>🗺️  C V E &nbsp; M A P</h1>
  <p><b>Continuous, Autonomous Vulnerability Intelligence Aggregation</b></p>
  <br>

[![Engine](https://img.shields.io/badge/Engine-Go_1.25-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![UI](https://img.shields.io/badge/Frontend-Glassmorphism-66FCF1?style=for-the-badge)](https://yadavnikhil17102004.github.io/CVE_Map_hehe/)
[![NVD](https://img.shields.io/badge/Intelligence-NVD_API-red?style=for-the-badge)](https://nvd.nist.gov/)
[![Action](https://img.shields.io/badge/Sync-Every_6_Hours-success?style=for-the-badge&logo=githubactions)](https://github.com/features/actions)

</div>

<br>

## ⚡ Executive Summary

**CVE Map** is a blistering-fast, native Go engine designed to autonomously scrape the GitHub API for documented CVE Proofs-of-Concept and live exploits across the internet. It compresses this raw data into highly optimized JSON signatures and visualizes the threat landscape via a live, native tracking dashboard.

**Why?** Because manual exploit hunting during an engagement is too slow. Speed is king. Time is access.

### 🌐 [Access the Live Threat Dashboard Here](https://yadavnikhil17102004.github.io/CVE_Map_hehe/)

---

## 🛠 Active Capabilities

- **Autonomous Aggregation:** An independent GitHub Actions workflow awakes every 6 hours, compiling the custom Go engine from source and hammering the GitHub indices for the latest uploaded exploits.
- **Zero-Latency NVD Integration:** The internal `nvd_scraper.go` engine mass-downloads and compresses the entire **US National Vulnerability Database (NVD)** directly into a localized hashmap. The frontend dashboard operates purely on static memory arrays—no API keys, no network rate limits, instantaneous UI.
- **O(N log N) Engine Design:** The engine leverages native `sort.SliceStable`, pre-allocated memory pools, and `strings.Builder` concatenation to parse thousands of repositories with zero garbage-collection thrashing.
- **Glassmorphism Web UI:** The `/web` directory serves a premium, Javascript-driven GUI natively through GitHub Pages, allowing granular search sorting by specific CVE ID, repository name, or year.

---

## 📡 Public CDN & Intelligence API

Because the `scrape.yml` automated workflow builds and commits raw JSON dictionaries directly into the structural tree, **GitHub Pages natively hosts the databases as a zero-cost API CDN**.

You can pull the raw, highly-minified intelligence datasets directly into your own tools.

### Query The Exploit Database (JSON)

Access the core exploit arrays categorized by year:

```bash
# Fetch 2024 Exploit Mappings
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/2024.json | jq '.cves[] | .cve_id'
```

### Query The NVD Hashmap Dictionary

Access our proprietary snapshot of the NIST vulnerability descriptions and CVSS scores:

```bash
# Structure: { "CVE-ID": { "s": "CVSS_Score", "v": "Severity", "d": "Description" } }
curl -s https://yadavnikhil17102004.github.io/CVE_Map_hehe/data/nvd_intel.json | jq '."CVE-2024-38063"'
```

---

## 🚀 Activation & Deployment

If you have forked or cloned this repository, follow these steps to ignite the engine on your own infrastructure:

1. **Activate the Scraper:**
   - Go to your repository's **Settings** -> **Actions** -> **General**.
   - Ensure `Allow all actions and reusable workflows` is enabled.
   - Go to your **Actions** tab, select the `Continuous Exploit Scraper` workflow, and smash **Run workflow**.
2. **Activate the Dashboard (GitHub Pages):**
   - Go to **Settings** -> **Pages**.
   - Set the Source to `Deploy from a branch`.
   - Set the Branch to `main` and the folder to `/` (Root).
   - Click Save. Your dashboard will go live at `https://<your-username>.github.io/<repo-name>/`.

---

> _"Secure by design is nice, but secure by penetration testing is truth."_
