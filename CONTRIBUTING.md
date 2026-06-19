# Contributing to CVE Map

Thanks for contributing.

## 1) Fork and clone

```bash
git clone https://github.com/<your-user>/CVE-Intel.git
cd CVE-Intel
```

## 2) Local prerequisites

- Go 1.25+
- Python 3
- Optional for full-data runs:
  - `SYNC_TOKEN` (GitHub token)
  - `NVD_API_KEY`

## 3) Run locally

```bash
./start.sh
# http://localhost:8000
```

## 4) Run scrapers manually

```bash
go build cvemapping.go && ./cvemapping -github-token="$SYNC_TOKEN"
go build nvd_scraper.go && ./nvd_scraper -nvd-key="$NVD_API_KEY"
go build news_scraper.go && ./news_scraper
```

## 5) Verification before PR

```bash
# build sanity
go build cvemapping.go && go build nvd_scraper.go && go build news_scraper.go

# optional frontend checks (if changing HTML/JS)
# run local and test search/filter flows in dashboard/news
```

## 6) Branching and commits

- Branch naming:
  - `feat/<topic>`
  - `fix/<topic>`
  - `docs/<topic>`
- Commit style:
  - `feat: ...`
  - `fix: ...`
  - `docs: ...`

## 7) Pull request checklist

- [ ] Change is scoped and minimal
- [ ] Build passes locally
- [ ] README/docs updated if behavior changed
- [ ] Added/updated issue reference if applicable
- [ ] No secrets or credentials committed

## 8) Good first contribution areas

- Docs and API reference improvements
- Frontend UX tweaks (filters/search states)
- Data quality checks and scraper resilience
- CI and test automation
