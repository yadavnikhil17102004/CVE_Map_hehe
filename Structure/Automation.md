# Automation (GitHub Actions)

> [!info] Purpose
> Automates the regular fetching, enrichment, and publishing of data so the static site stays up‑to‑date without manual intervention.

## ⏰ Workflows
| Workflow | Schedule | Main Jobs | Output |
|----------|----------|-----------|--------|
| **scrape.yml** | Every 6 hours (`cron: '0 */6 * * *'`) | - Build Go binaries<br>- Run `cvemapping.go`<br>- Run `nvd_scraper.go`<br>- Commit updated `data/` JSON | `data/YYYY.json`, `data/nvd_intel_YYYY.json`, `data/nvd_intel.json` |
| **news.yml** | Hourly (`cron: '0 * * * *'`) | - Build Go binary<br>- Run `news_scraper.go`<br>- Commit only `data/news.json` | `data/news.json` |

## 📂 Workflow Files
- `.github/workflows/scrape.yml`
- `.github/workflows/news.yml`

## 🔧 Typical Job Steps (scrape.yml)
```yaml
name: Scrape

on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:   # allow manual trigger

jobs:
  build-and-run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - name: Build cvemapping
        run: go build -o cvemapping cvemapping.go
      - name: Run cvemapping
        env:
          SYNC_TOKEN: ${{ secrets.SYNC_TOKEN }}
        run: ./cvemapping -github-token="$SYNC_TOKEN"
      - name: Build nvd_scraper
        run: go build -o nvd_scraper nvd_scraper.go
      - name: Run nvd_scraper
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: ./nvd_scraper -nvd-key="$NVD_API_KEY"
      - name: Commit changes
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add data/
          git commit -m "Update CVE and NVD data ($(date +%Y-%m-%d_%H:%M:%S))" || echo "No changes"
          git push
```

## 🔧 Typical Job Steps (news.yml)
```yaml
name: News

on:
  schedule:
    - cron: '0 * * * *'
  workflow_dispatch:

jobs:
  build-and-run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - name: Build news_scraper
        run: go build -o news_scraper news_scraper.go
      - name: Run news_scraper
        run: ./news_scraper
      - name: Commit news.json
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add data/news.json
          git commit -m "Update news feed ($(date +%Y-%m-%d_%H:%M:%S))" || echo "No changes"
          git push
```

## 🔐 Required Secrets
Set in **Settings → Secrets and variables → Actions**:
- `SYNC_TOKEN` – GitHub personal access token (required for authenticated API requests in `cvemapping`).
- `NVD_API_KEY` – (Optional but recommended) key for NVD API to avoid rate limits.

## 🚀 Manual Trigger
Both workflows support `workflow_dispatch`, allowing you to run them from the Actions tab for testing or immediate updates.

## 📦 Deploy
- The workflows push directly to the branch that GitHub Pages is configured to serve (usually `gh-pages` or the `docs/` folder on `main`).  
- No separate deployment step is needed; updating the `data/` JSON files automatically refreshes the site because the frontend fetches them at runtime.

## 🛡️ Safety & Idempotency
- Scrapers are designed to be idempotent: running them multiple times produces the same output (they merge new data with existing files).
- If a step fails, the workflow stops and no commit is made (unless you explicitly allow partial commits; current implementation only commits on success).
- The `git commit` step includes a check for changes; if nothing changed, it avoids creating an empty commit.

## 📂 Related Files
- **Workflow definitions:** `.github/workflows/scrape.yml`, `.github/workflows/news.yml`
- **Scraper source:** `cvemapping.go`, `nvd_scraper.go`, `news_scraper.go`
- **Data destination:** `data/` directory

## 🏷️ Tags
`#automation #github-actions #ci-cd #data-pipeline #scheduled #go`
