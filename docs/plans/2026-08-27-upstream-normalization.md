# Upstream normalization — Elasticsearch / GCTI feed quality

> **For agentic workers:** Implement task-by-task; validate after each. See also [`plan.md`](../../plan.md) (audit track).

**Goal:** Fix CVE id truncation and enrich exports so downstream (`poc-gcti-cve-catalog`, `poc-gcti-cve-exploits-v1`) can ingest without duplicate Python compensations.

**Do not break:** dashboard, `data/YYYY.json` shape for current consumers, scrape workflows, or `nvd_intel*.json` compact keys (additive only).

**Context:** Downstream ingests this repo into Elasticsearch as gcti-shaped indices. Fixes here remove duplicate parsing and improve Intel Library / ChatIntel feed quality.

---

## Priority order

| # | Task | Status |
|---|------|--------|
| U0 | P0 — Strict CVE regex in `cvemapping.go` + `validate.go` alignment | ✅ Code done (data rescrape pending) |
| U1 | P1 — `inferred_cve_ids` + mapping metadata on repos | ⬜ |
| U2 | P1 — NVD compact `m` (`last_modified`) | ⬜ |
| U3 | P2 — CI validation hardening (fail on bad bucket keys) | ⬜ |
| U4 | P2 — OTHER bucket docs (+ optional `unmapped_repos_{year}.json`) | ⬜ |
| U5 | P3 — Optional `data/exploits_{year}.json` | ⬜ |

---

## U0 — P0: Fix CVE id truncation (DONE in code)

### Goal
Stop year-scoped `\d+` regex from creating truncated bucket keys like `CVE-2026-442` when the real id is `CVE-2026-44289`.

### What we did
- Added `findStrictCVEIDs()` using `(?i)CVE-\d{4}-\d{4,}` + `^CVE-\d{4}-\d{4,}$` validation
- Updated `exportToJSON()` and `processRepos()` to use strict matching
- Updated `validate.go`: strict pattern; `OTHER-YYYY` warns; legacy truncated buckets warn (not fail until U3)

### Test
```bash
go test -run TestFindStrictCVEIDs ./...
go test -run TestExportToJSONGroupingUsesStrictCVEIDs ./...
go run validate.go   # passes; warns on legacy truncated buckets in committed data
```

### Manual cases (after rescrape)
| Input | Expected |
|-------|----------|
| Repo `CVE-2026-442_`, desc `CVE-2026-44289` | Bucket `CVE-2026-44289` |
| No CVE in text | `OTHER-2026` |
| Multi-CVE repo | Under each valid CVE bucket |

### Rescrape required
Committed `data/YYYY.json` still contains legacy truncated keys until scrape workflow runs with updated `cvemapping`.

---

## U1 — P1: Per-repo inferred CVE ids

### Goal
Expose all strict CVE ids found in repo text for downstream exploit pipelines, even when bucket key differs.

### How
Extend `CVERepository` in `cvemapping.go`:

```json
{
  "inferred_cve_ids": ["CVE-2026-44289"],
  "mapping_parent_cve_id": "CVE-2026-44289",
  "mapping_bucket": "strict"
}
```

| Field | Meaning |
|-------|---------|
| `inferred_cve_ids` | All strict CVEs from name + full_name + description + topics |
| `mapping_parent_cve_id` | Bucket key this export pass used |
| `mapping_bucket` | `strict` \| `other` \| `truncated` |

### Test
```bash
go test -run TestInferredCVEIDs ./...
# After export: jq '.cves[] | select(.repositories[0].inferred_cve_ids != null)' data/2026.json
```

---

## U2 — P1: NVD compact `last_modified`

### Goal
Add `m` key to `CVEIntel` from NVD `lastModified` (date-truncated like `p`).

### How
`nvd_scraper.go` → `CVEIntel.LastModified` with `json:"m,omitempty"`, populate in `extractIntel()`.

### Test
```bash
go run nvd_scraper.go   # needs NVD_API_KEY optional
jq 'to_entries[0].value | has("m")' data/nvd_intel_2026.json
go run validate.go
```

---

## U3 — P2: CI validation hardening

### Goal
Fail CI when year file `cve_id` is not `CVE-YYYY-NNNN+` or `OTHER-YYYY`.

### How
Upgrade `validate.go` warnings → `addFail` for invalid buckets (after U0 rescrape on main).

Optional: JSON Schema in `schemas/` + CI step.

### Test
```bash
go run validate.go   # must pass on clean data
# Inject fake "CVE-2026-442" bucket → must exit 1
```

---

## U4 — P2: OTHER bucket hygiene (docs)

### Goal
Document that `OTHER-{year}` is not a CVE; repos may still have `inferred_cve_ids`.

### How
README section + optional `data/unmapped_repos_{year}.json`.

---

## U5 — P3: Exploit-shaped export (optional)

New artifact `data/exploits_{year}.json` — one row per `github_repo_id`, union `cve_ids`.

### Test
Dedupe by `github_repo_id`; same repo under two CVE buckets → one row, merged `cve_ids`.

---

## Out of scope

- Do not remove `OTHER-{year}` bucket (dashboard depends on it)
- Do not change GitHub scrape pagination
- Do not rename existing JSON fields

## PAT / secrets

- **U0–U4 code + unit tests:** no PAT
- **Rescrape / NVD regen:** `SYNC_TOKEN`, optional `NVD_API_KEY` in CI or your local env
