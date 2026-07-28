# CVE-Intel Roadmap

This roadmap captures planned work that was intentionally deferred during VPS migration hardening and launch prep. It is ordered by value-to-effort and operational safety.

## Current baseline (live)

- VPS-hosted stack is live: Postgres + FastAPI + static frontend.
- Public hostname is active: `https://cve-intel.duckdns.org`.
- API is primary integration surface (`/api/*`), with docs at `/docs`.
- Weekly public snapshots are distributed via GitHub Releases (not git history commits).
- Legacy static-era snapshot is preserved at git tag: `legacy-static-v1`.

## Recently completed (2026-07-28)

1. Replaced dashboard cross-year client fan-out with server-side paginated `/api/search` flow.
2. Added API pagination/scoping primitives (`/api/cve/{year}` pagination, `/api/intel/{year}` pagination + `cve_ids` filter).

## Near-term priorities (high ROI, low/medium effort)

1. Add explicit paginated result UX for global search (show/next cursor style controls and total-match messaging polish).
2. Add CVE detail route/view combining repo + NVD + related news context.
3. Add shareable deep links for query/filter state.
4. Validate and tune production response caching after VPS deploy of latest API revision.

## Part 5 backlog — repo trust/risk intelligence

Goal: rank PoC repositories with transparent confidence and caution signals, without hiding data.

### 5.1 Trust score model (planned)

Use two outputs per repo:

- `trust_score` (0-100): quality/legitimacy ranking.
- `risk_flags[]`: explicit caution indicators (never silent filtering).

Proposed weighted model:

1. Relevance quality (35%)
2. Recency/maintenance (25%)
3. Community validation, bot-resistant weighting (20%)
4. Repo hygiene signals (20%)

### 5.2 Signals already available (no extra scraping required)

- Stars/forks/language/topics/owner metadata.
- Repo age and update timestamps.
- Historical presence signal (`last_seen_in_scrape_at`).
- CVE-side product/weakness/context from NVD enrichment.

### 5.3 Signals requiring additional collection

- Commit history depth, contributors, watchers/issues, release cadence.
- README/license quality parsing beyond current metadata.
- Heuristic static risk features from repository content.

### 5.4 Malicious-repo risk flagging (planned, phased)

Phase A (cheap, local heuristics):

- suspicious freshness/star anomalies
- repetitive account/repo patterns
- low-content/high-keyword spam patterns

Phase B (optional external enrichment):

- VirusTotal or similar reputation checks
- threat-intel list joins for known malicious PoC repos

UI principle:

- show everything with visible caution badges
- do not silently suppress records

## Part 6 backlog — news intelligence upgrade path

Goal: evolve from plain RSS listing into CVE-linked, deduplicated, triage-friendly intelligence.

### 6.1 CVE extraction and linking (top priority)

- Extract CVE IDs from title/description text via regex.
- Persist `mentioned_cves[]` and link articles to CVE records.
- Enable "CVEs currently in the news" view.

### 6.2 Cross-source deduplication/clustering

- Cluster same event across feeds by CVE overlap + time window + title similarity.
- Present one event with source fan-out rather than duplicate cards.

### 6.3 Article classification + summary

- Classify: advisory / exploit release / active exploitation / breach / research.
- Add one-line summary per article.
- Start rule-based; optionally use lightweight LLM calls when rule confidence is low.

### 6.4 Trending CVE detection

- Mention-frequency spike detection over rolling windows.
- Surface "rising CVEs" as an early-warning feed.

## Architecture decision note

No frontend framework rebuild is required to ship Parts 5/6. Most value can be delivered backend-first, then surfaced in the existing frontend incrementally.

## Deferred by design (not dropped)

- Full framework rebuild (React/Vue/etc.) unless/until product complexity justifies it.
- Advanced graph UI and multi-workspace interaction model.
