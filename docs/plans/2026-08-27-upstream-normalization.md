# Upstream normalization — Elasticsearch / GCTI feed quality

> **For agentic workers:** Implement task-by-task; validate after each. See also [`plan.md`](../../plan.md) (audit track).

**Goal:** Fix CVE id truncation and enrich exports so downstream (`poc-gcti-cve-catalog`, `poc-gcti-cve-exploits-v1`) can ingest without duplicate Python compensations.

**Do not break:** dashboard, `data/YYYY.json` shape for current consumers, scrape workflows, or `nvd_intel*.json` compact keys (additive only).

**Context:** Downstream ingests this repo into Elasticsearch as gcti-shaped indices. Fixes here remove duplicate parsing and improve Intel Library / ChatIntel feed quality.

---

## Priority order

| # | Task | Status |
|---|------|--------|
| U0 | P0 — Strict CVE regex in `cvemapping.go` + `validate.go` alignment | ✅ Shipped (`926572ab`) |
| U1 | P1 — `inferred_cve_ids` + mapping metadata on repos | ✅ Code shipped (rescrape pending) |
| U2 | P1 — NVD compact `m` (`last_modified`) | ✅ Code shipped (nvd regen pending) |
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

## U1 — P1a: Per-repo inferred CVE ids (SHIPPED in code)

### Bucket model (downstream-aligned)
- **Dashboard bucket key:** strict CVE ids from `name + full_name` only
- **Description/topics CVEs:** stay under `OTHER-{year}`; link via `inferred_cve_ids`
- **`mapping_bucket`:** `strict` | `other` | `truncated` (legacy regex would have truncated)

### Additive repo fields
```json
{
  "inferred_cve_ids": ["CVE-2021-22681"],
  "mapping_parent_cve_id": "OTHER-2026",
  "mapping_bucket": "other"
}
```

### Test case
`pcrosby-1990/cip-security-poc` (`github-1318671575`) → `OTHER-2026` + `inferred_cve_ids: ["CVE-2021-22681"]`

---

## U2 — P1b: NVD compact `m` (SHIPPED in code)

`CVEIntel` adds `m` (YYYY-MM-DD) from NVD `lastModified`. Regenerate `nvd_intel*.json` on next scrape.

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
