# Contributing to CVE Map

Thanks for contributing. Keep changes small, verify them locally, and avoid touching generated assets unless the change requires it.

## 1) Fork and clone

```bash
git clone https://github.com/<your-user>/CVE-Intel.git
cd CVE-Intel
```

## 2) Local prerequisites

Required:
- Go 1.25+
- Python 3

Optional for live/full-data runs:
- `SYNC_TOKEN` — GitHub token for the GitHub CVE mapping scraper
- `NVD_API_KEY` — NVD API key for higher throughput

If you have `gh` installed, make sure it is authenticated too:
```bash
gh auth status
```

## 3) Run locally

Start the local site:

```bash
./start.sh
# opens or serves the site on http://localhost:8000
```

If you only want a static preview, any simple HTTP server works:

```bash
python3 -m http.server 8000
```

Pages to check locally:
- `http://localhost:8000/index.html`
- `http://localhost:8000/dashboard.html`
- `http://localhost:8000/news.html`
- `http://localhost:8000/docs.html`

## 4) Run scrapers manually

```bash
go build cvemapping.go && ./cvemapping -github-token="$SYNC_TOKEN"
go build nvd_scraper.go && ./nvd_scraper -nvd-key="$NVD_API_KEY"
go build news_scraper.go && ./news_scraper
```

Notes:
- These commands regenerate `data/*.json`.
- Do not hand-edit generated JSON unless you are fixing a data bug.
- `style.css` is generated output; do not edit it directly.

## 5) Local UI testing steps

If you change any HTML, JS, or styling, verify the actual browser behavior:

1. Load the dashboard and make sure the table renders.
2. Search for a known CVE or repository keyword.
3. Change year selection and confirm results update.
4. Exercise the severity and KEV filters.
5. Open the news page and test keyword search plus tier filtering.
6. Check the browser console for fetch/runtime errors.

Minimal build sanity:

```bash
go build cvemapping.go && go build nvd_scraper.go && go build news_scraper.go
```

## 6) Branching and commits

Branch naming:
- `feat/<topic>`
- `fix/<topic>`
- `docs/<topic>`

Commit style:
- `feat: ...`
- `fix: ...`
- `docs: ...`

Prefer one concern per commit. If a docs change and code change are unrelated, split them.

## 7) Pull request checklist

- [ ] Change is scoped and minimal
- [ ] Build passes locally
- [ ] Local UI checks passed for any frontend change
- [ ] README/docs updated if behavior changed
- [ ] Issue reference added when applicable
- [ ] No secrets or credentials committed
- [ ] Generated files only changed when intentionally regenerated

## 8) Good first contribution areas

- Docs and API reference improvements
- Frontend UX tweaks (filters/search states)
- Data quality checks and scraper resilience
- CI and test automation
