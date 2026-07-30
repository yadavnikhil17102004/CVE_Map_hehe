# UX Blueprint (Capability-Audit First)

This blueprint is derived from repository source inspection, not assumptions. Where a statement is inferred (not directly represented in code), it is labeled **Inference**.

## 1. Capability inventory

### API runtime characteristics (global)
- Base app uses FastAPI with global gzip middleware (`minimum_size=1024`) and default rate limit `240/minute`. (`api/main.py`)
- Endpoint responses are serialized through `make_json_response(...)` and may include per-route `Cache-Control` headers. (`api/main.py`)

### `GET /api/health`
- Purpose: liveness + DB connectivity check.
- Parameters: none.
- Rate limit: `60/minute`.
- Response shape:
  - `ok` (bool)
  - `service` (string, currently `cve-intel-api`)
- Cache behavior: none explicitly set.
- Pagination: none.
- Current UI surface: none found in frontend pages.

### `GET /api/cve/{year}`
- Purpose: CVE -> mapped repo records for a year from `cve_repos`.
- Parameters:
  - `year` path (1999..2100)
  - optional `page` (>=1): enabling pagination mode
  - `per_page` (1..500, default 200)
- Rate limit: `90/minute`.
- Response (non-paginated):
  - `year`
  - `cves[]`:
    - `cve_id`
    - `repositories[]` with fields:
      - `id`
      - `name`
      - `full_name`
      - `html_url`
      - `description`
      - `stargazers_count`
      - `forks_count`
      - `language`
      - `updated_at`
      - `pushed_at`
      - `created_at`
      - `topics[]`
      - `owner.login`
      - `owner.html_url`
      - `clone_url`
      - `has_code`
      - `age_days`
- Response (paginated): above + `page`, `per_page`, `total`.
- Cache behavior: `Cache-Control: public, max-age=300`.
- Current UI surface:
  - `dashboard.html` and `index.html` consume this endpoint.
  - Current pages generally use unpaginated yearly calls in main flows.

### `GET /api/intel/{year}`
- Purpose: CVE -> compact NVD intel map for a year from `nvd_intel`.
- Parameters:
  - `year` path (1999..2100)
  - optional `page` (>=1)
  - `per_page` (1..5000, default 1000)
  - optional `cve_ids` (comma-separated; up to 5000 IDs)
- Rate limit: `90/minute`.
- Response (non-paginated): object keyed by `CVE-ID`, value compact fields:
  - `s` (`cvss_score`)
  - `v` (`severity`)
  - `d` (`description`)
  - `c` (`cvss_vector`)
  - `w` (`cwe`)
  - `r` (`source`)
  - `p` (`published_date`)
  - `u` (`status`)
  - `e` (`epss_score`)
  - `k` (`kev_flag`, emitted only when true)
  - `q` (`products`, emitted when present)
- Response (paginated): `year`, `page`, `per_page`, `total`, `intel` map.
- Cache behavior: `Cache-Control: public, max-age=300`.
- Current UI surface:
  - `dashboard.html` uses this heavily for filters/badges/detail panel.
  - `docs.html` consumes this for metric cards.

### `GET /api/intel-summary/{year}`
- Purpose: compact intel only for CVEs that appear in `cve_repos` for that year (smaller payload than full-year intel).
- Parameters: `year` path.
- Rate limit: `120/minute`.
- Response: same compact key format as `/api/intel/{year}` keyed by CVE.
- Cache behavior: `Cache-Control: public, max-age=300`.
- Current UI surface:
  - `index.html` uses this for homepage-level aggregate logic.

### `GET /api/news`
- Purpose: latest news feed from `news_items`.
- Parameters:
  - `limit` (1..500, default 200)
- Rate limit: `120/minute`.
- Response:
  - `last_updated`
  - `articles[]` with:
    - `title`
    - `link`
    - `description`
    - `pub_date`
    - `source`
    - `tier`
    - `image_url`
- Cache behavior: `Cache-Control: public, max-age=120`.
- Current UI surface:
  - `news.html`, `dashboard.html` activity feed, `index.html` live intel section.

### `GET /api/search`
- Purpose: global CVE/repo/intel search via joined `cve_repos` + `nvd_intel`.
- Parameters:
  - required `q` (2..200)
  - `page` (>=1, default 1)
  - `per_page` (1..200, default 50)
  - optional `year` (1999..2100)
  - optional `severity` (`LOW|MEDIUM|HIGH|CRITICAL`)
  - optional `kev` (boolean)
- Rate limit: `120/minute`.
- Response:
  - `query`, `page`, `per_page`, `total`
  - `cves[]` each with:
    - `year`
    - `cve_id`
    - `repositories[]` (same full repo shape as `/api/cve/{year}`)
    - optional `intel` (same compact format as `/api/intel/{year}`)
- Cache behavior: `Cache-Control: no-store`.
- Current UI surface:
  - `dashboard.html` global search path uses this endpoint.

### Data/API capabilities with no or weak UI surface today
- `/api/health` is not surfaced in user UI.
- `/api/intel/{year}` `cve_ids` scoping is not surfaced as a first-class UI control.
- Pagination metadata (`total`, `page`, `per_page`) exists across several endpoints, but frontend flows are still largely list-first without explicit paginated navigation UX.
- Search endpoint has server-side `year`, `severity`, `kev` filters, but current UX emphasizes local interactions and does not expose all server filtering capabilities as explicit query-builder controls.
- Multiple DB-level NVD fidelity fields exist but are not exposed in API responses at all (details below).

### DB-modeled data not currently exposed by API
From migration SQL and loaders, `nvd_intel` contains additional fidelity fields not returned by current API responses:
- `cvss_v31_score`, `cvss_v31_vector`, `cvss_v31_severity`
- `cvss_v30_score`, `cvss_v30_vector`, `cvss_v30_severity`
- `cvss_v2_score`, `cvss_v2_vector`, `cvss_v2_severity`
- `nvd_references` (JSONB)
- `cpe_configurations` (JSONB)
- `weaknesses` (JSONB)
- `vendor_comments` (JSONB)
- `source_identifier`
- `vuln_status`
- `last_modified_date`
- `epss_percentile`

Additional modeled-but-unsurfaced operational tables:
- `nvd_backfill_checkpoint`
- `nvd_backfill_runs`

Additional modeled-but-unsurfaced row metadata:
- `cve_repos.last_seen_in_scrape_at` (tracked in migration follow-up)

## 2. Entity relationships

### Verified relations in query usage
- `cve_repos` is the CVE-to-repository mapping base.
- `nvd_intel` joins to CVEs by `cve_id`.
- `news_items` is currently independent in API joins; it is consumed as a separate feed.
- Search uses a `LEFT JOIN` from `cve_repos` to `nvd_intel` on `cve_id`.
- `intel-summary` builds CVE set from `cve_repos` (year-scoped), then left-joins `nvd_intel`.

### Practical workflow implications
Natural supported workflows:
- Start from a year -> list CVEs with known PoC repos (`/api/cve/{year}`) -> enrich with NVD context (`/api/intel/{year}` or `intel` embedded via `/api/search`).
- Start from keyword/CVE/repo owner -> `/api/search` returns CVE rows with repo and optional intel context.
- Start from threat-news stream -> inspect article metadata/tier quickly (`/api/news`).

Less directly supported without extra API work:
- “Show all news linked to this CVE” (no current API-level CVE-news join).
- “Group by vendor/product/CPE across years” (DB has product/config fields, but API currently returns compact map fields only).
- “Historical trend by NVD last-modified semantics” (DB stores `last_modified_date`, but API does not expose it).

## 3. Information architecture

Proposed architecture should follow data shape, not current page split:

1. **Triage (Action-first)**
- Primary list of CVEs with urgency indicators and fast filters.
- Backed by `/api/search` (for query/filter/pagination) plus `intel` compact fields.

2. **CVE Workspace (Entity-first)**
- Single CVE detail workspace with tabs/sections:
  - Repositories (`cve_repos` fields)
  - NVD/KEV/EPSS context (compact + extended when available)
  - Related news mentions (**Inference**: requires future CVE-news linking endpoint or extraction work from roadmap).

3. **News Intel Stream**
- Feed-centric view with tier/source/time controls and optional CVE-linked facets once available.

4. **Operations/Freshness Surface**
- Read-only ops indicators relevant to trust in data freshness:
  - last scrape success recency, last news update, snapshot age.
- This should be thin and not replace runbook tooling.

Reasoning:
- The backend is entity-rich around CVE IDs and repo mappings; workflows should pivot around that identity key.
- News is currently decoupled from CVE entities; keep it as its own stream until linking exists.
- Operational freshness materially affects user confidence in threat data, and those signals are already present in ops artifacts/docs.

## 4. User workflows

### Workflow A: “What is urgent right now?”
- User wants highest-risk CVEs with exploitation evidence.
- Data path:
  - `/api/search` with severity/kev filters
  - compact intel fields (`s`,`v`,`k`,`e`) and repo counts from `repositories[]`.
- Outcome: prioritized list with quick drill-down.

### Workflow B: “Does CVE-X have public PoC activity?”
- User pastes CVE ID.
- Data path:
  - `/api/search?q=CVE-...`
  - fallback year-based `/api/cve/{year}` if needed.
- Outcome: PoC presence, repo quality/activity, NVD severity context.

### Workflow C: “Show me this year’s exposure shape”
- User compares counts/severity mix and mapped-CVE footprint across years.
- Data path:
  - `/api/cve/{year}` (possibly paginated)
  - `/api/intel-summary/{year}` for lightweight severity/KEV/EPSS aggregates.
- Outcome: year-over-year threat posture from mapped CVEs.

### Workflow D: “Catch up on security news with priority signal”
- User scans high-tier stories first.
- Data path:
  - `/api/news?limit=...`
- Outcome: triaged feed by tier/source/time.

## 5. Recommended surfaces

### For Workflow A (urgent triage)
- Surface: Filterable + paginated CVE table.
- Data source: `/api/search`.
- Columns/signals:
  - `cve_id`, `year`
  - severity/CVSS from `intel.v` + `intel.s`
  - KEV from `intel.k`
  - EPSS from `intel.e`
  - repo count = `repositories.length`
  - activity proxy = max repo `pushed_at`
- Controls:
  - text query, severity, KEV toggle, year filter, page/per_page, sort.

### For Workflow B (single CVE lookup)
- Surface: CVE detail panel/page.
- Data source: `/api/search` (single-result mode) + optionally `/api/cve/{year}`.
- Sections:
  - NVD summary (description/cwe/vector/status/source/published_date)
  - repo list with owner/language/stars/forks/updated
  - quick outbound links (NVD, GitHub search).

### For Workflow C (year posture)
- Surface: Year dashboard cards + severity/KEV/EPSS distribution widgets.
- Data source:
  - `/api/intel-summary/{year}` for cheap aggregate load
  - drill path to `/api/cve/{year}?page=...`.
- Controls:
  - year switcher
  - optional “mapped CVEs only” explanation because summary is repo-linked.

### For Workflow D (news)
- Surface: News stream with tier/source filters and recentness grouping.
- Data source: `/api/news`.
- Fields:
  - `title`, `source`, `tier`, `pub_date`, `description`, `link`, `image_url`.
- Optional enhancement:
  - CVE mention chips once roadmap CVE extraction ships.

## 6. Prioritization

Prioritization here is based on actionability and current data coverage patterns exposed by API/frontend.

### Tier 1 (always visible at glance)
- `cve_id`
- Severity + CVSS (`intel.v`, `intel.s`)
- KEV (`intel.k`)
- EPSS (`intel.e`, when present)
- Repo count / recent activity (`repositories.length`, `pushed_at`)
- Data freshness badge (scrape/news recency)

### Tier 2 (one click deeper)
- `description`, `cwe`, `cvss_vector`, `status`, `source`, `published_date`
- Top repositories with owner/language/stars/forks
- News article snippets and source attribution

### Tier 3 (reference/detail)
- `clone_url`, repo topics full list, raw timestamps
- Operational mechanics details (timer names, runbook internals)
- Extended NVD fidelity fields once exposed (`weaknesses`, `references`, CVSS version breakdowns)

Rationale:
- Tier 1 is what directly drives triage/response action.
- Tier 2 supports decision confidence once item is selected.
- Tier 3 is valuable but should not compete with urgency cues.

## 7. Consolidation and simplification opportunities

- Consolidate cross-page CVE intelligence logic:
  - `dashboard.html`, `index.html`, `docs.html` each independently compute partial severity/intel insights; centralize around one query model to reduce drift.
- Move more list loading to `/api/search` with explicit pagination controls instead of mixed local filtering over large year payloads.
- Keep `/api/intel-summary/{year}` as default aggregate source for year-overview views; reserve full `/api/intel/{year}` for drill workflows.
- Simplify duplicated “news mini-feed vs news page” logic by sharing tier/date normalization behavior.
- Current frontend still has endpoint usage that is task-ambiguous:
  - docs-page metric visualizations using full-year pulls without explicit user workflow framing.

## 8. Underused-capability highlights

Highest-leverage backend capabilities already present but underused in UI:

1. Server-side paginated + filtered `/api/search` already returns merged CVE + repo + intel context; this can be the primary triage backbone without extra backend work.
2. `/api/intel/{year}` supports `cve_ids` scoped retrieval (ideal for detail-panel lazy-loading), but UI currently does not expose this targeted fetch pattern.
3. `intel-summary` route provides much cheaper year-level intel aggregation and should back all at-a-glance yearly widgets.
4. DB already contains richer NVD fidelity fields (`weaknesses`, `references`, multi-version CVSS, `epss_percentile`, etc.) that are currently hidden by API response shaping.
5. `last_seen_in_scrape_at` exists for repo presence stability/risk heuristics and can power trust/freshness cues with no new scraping.
6. Ops freshness/state artifacts are mature enough to provide user-visible “data freshness confidence” signals in UI.

