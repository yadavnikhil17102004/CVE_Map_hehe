# Data Layer Upgrades — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve data quality, reduce frontend payload size, add EPSS scores + CPE product mapping, fix repo bloat with orphan data branch, and add scraper health checks.

**Architecture:** All changes are additive to `nvd_scraper.go` (new fields on `CVEIntel`, new EPSS scraper phase, CPE extraction). Frontend fetches per-year intel files instead of one monolithic 18MB file. Git data isolation handled via workflow change.

**Tech Stack:** Go 1.25 (stdlib only), GitHub Actions, static JSON on GitHub Pages, vanilla JS.

---

## Task 1: Split `nvd_intel.json` into per-year files

**Files:**
- Modify: `nvd_scraper.go` (output logic at lines 161–172)
- Modify: `dashboard.html` (nvd fetch at line 335)

### Why
18MB monolithic file fetched on every page load. Per-year split means ~1–2MB per year view instead of 18MB always.

- [ ] **Step 1: Update `CVEIntel` output path in `nvd_scraper.go`**

Replace the single-file write block (lines 161–172) with a function that partitions by year:

```go
// writeIntelByYear splits the dictionary into data/nvd_intel_{year}.json files.
// It also writes data/nvd_intel.json as a full fallback for the public API.
func writeIntelByYear(dictionary map[string]CVEIntel) {
	byYear := make(map[string]map[string]CVEIntel)
	yearRegex := regexp.MustCompile(`^CVE-(\d{4})-`)
	for id, intel := range dictionary {
		m := yearRegex.FindStringSubmatch(id)
		if m == nil {
			continue
		}
		y := m[1]
		if byYear[y] == nil {
			byYear[y] = make(map[string]CVEIntel)
		}
		byYear[y][id] = intel
	}
	for year, slice := range byYear {
		out, err := json.Marshal(slice)
		if err != nil {
			log.Printf("[-] Failed to marshal year %s: %v", year, err)
			continue
		}
		path := filepath.Join("data", fmt.Sprintf("nvd_intel_%s.json", year))
		if err := os.WriteFile(path, out, 0644); err != nil {
			log.Printf("[-] Failed to write %s: %v", path, err)
		} else {
			log.Printf("[+] Wrote %s (%d CVEs, %.1f KB)", path, len(slice), float64(len(out))/1024.0)
		}
	}
	// Also write full file for public API consumers
	full, _ := json.Marshal(dictionary)
	os.WriteFile(filepath.Join("data", "nvd_intel.json"), full, 0644)
}
```

Add `yearRegex := regexp.MustCompile(...)` import — `regexp` already imported. Replace the existing write block:

```go
// ── Write output ─────────────────────────────────────────
writeIntelByYear(dictionary)
elapsed := time.Since(start).Round(time.Millisecond)
log.Printf("[+] Done in %s. Dictionary: %d signatures.", elapsed, len(dictionary))
```

- [ ] **Step 2: Update `dashboard.html` — fetch per-year intel on year select**

Replace the boot fetch of the full `nvd_intel.json` (line 334–337):

```js
// Remove this from DOMContentLoaded:
// const r = await fetch('data/nvd_intel.json');
// if (r.ok) nvdLayer = await r.json();
```

Add a helper that loads per-year intel lazily (add after `let yearCache = {};` near line 324):

```js
let nvdCache = {}; // per-year NVD intel cache

async function loadNvdIntel(year) {
  if (nvdCache[year]) return nvdCache[year];
  try {
    const r = await fetch(`data/nvd_intel_${year}.json`);
    if (r.ok) nvdCache[year] = await r.json();
  } catch(_) {}
  return nvdCache[year] || {};
}
```

In `loadYear(year)` (line 392), after fetching the year JSON, add:

```js
nvdLayer = await loadNvdIntel(year);
```

- [ ] **Step 3: Build and verify locally**

```bash
go build nvd_scraper.go
./nvd_scraper  # will use existing nvd_intel.json as input — generates nvd_intel_YYYY.json files
ls -lh data/nvd_intel_*.json
```

Expected: one file per year present in data/, sizes 50KB–3MB.

- [ ] **Step 4: Open dashboard in browser and verify NVD modal still works**

```bash
./start.sh
```

Click any CVE row — modal should still show CVSS score, severity, KEV badge. Open browser console — no errors on nvd_intel fetch.

- [ ] **Step 5: Commit**

```bash
git add nvd_scraper.go dashboard.html data/nvd_intel_*.json
git commit -m "feat(data): split nvd_intel.json into per-year files, lazy-load in dashboard"
```

---

## Task 2: Add EPSS scores to `CVEIntel`

**Files:**
- Modify: `nvd_scraper.go` (add `EPSSScore float64` to `CVEIntel`, add Phase 3)
- Modify: `dashboard.html` (display EPSS in modal)

### Why
EPSS (Exploit Prediction Scoring System) fills the gap between CVSS severity and CISA KEV. CVSS = how bad if exploited. KEV = already exploited. EPSS = probability of exploitation in next 30 days. Free API from FIRST.org, batch endpoint returns 100 CVEs per call.

- [ ] **Step 1: Add `EPSSScore` field to `CVEIntel` struct**

In `nvd_scraper.go`, add to `CVEIntel`:

```go
type CVEIntel struct {
	Score     float64 `json:"s"`
	Severity  string  `json:"v"`
	Desc      string  `json:"d"`
	Vector    string  `json:"c,omitempty"`
	CWE       string  `json:"w,omitempty"`
	KEV       bool    `json:"k,omitempty"`
	Source    string  `json:"r,omitempty"`
	Published string  `json:"p,omitempty"`
	Status    string  `json:"u,omitempty"`
	EPSS      float64 `json:"e,omitempty"` // EPSS probability 0.0–1.0
}
```

- [ ] **Step 2: Add EPSS response structs**

```go
type EPSSResponse struct {
	Status     string      `json:"status"`
	StatusCode int         `json:"status-code"`
	Data       []EPSSEntry `json:"data"`
}

type EPSSEntry struct {
	CVE        string  `json:"cve"`
	EPSS       string  `json:"epss"`       // returned as string e.g. "0.97345"
	Percentile string  `json:"percentile"` // not used, but part of response
}
```

- [ ] **Step 3: Add `fetchEPSS` function**

FIRST.org batch endpoint accepts up to 100 CVE IDs per request via `?cve=CVE-A,CVE-B,...`.

```go
// fetchEPSS fetches EPSS scores for up to 100 CVE IDs at a time.
// Returns a map of CVE ID → EPSS probability (0.0–1.0).
func fetchEPSS(cveIDs []string) map[string]float64 {
	result := make(map[string]float64)
	client := &http.Client{Timeout: 30 * time.Second}

	for i := 0; i < len(cveIDs); i += 100 {
		end := i + 100
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]
		url := "https://api.first.org/data/1.0/epss?cve=" + strings.Join(batch, ",")

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("  [-] EPSS fetch error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var epssResp EPSSResponse
		if err := json.Unmarshal(body, &epssResp); err != nil {
			log.Printf("  [-] EPSS parse error: %v", err)
			continue
		}
		for _, entry := range epssResp.Data {
			score, err := strconv.ParseFloat(entry.EPSS, 64)
			if err == nil {
				result[entry.CVE] = score
			}
		}
		time.Sleep(1 * time.Second) // FIRST.org is generous but be polite
	}
	return result
}
```

- [ ] **Step 4: Add Phase 3 to `main()` — EPSS enrichment**

After the existing Phase 2 block and before `writeIntelByYear`:

```go
// ── Phase 3: EPSS enrichment ─────────────────────────────
// Fetch EPSS probability scores for all CVEs in dictionary.
log.Println("[+] Phase 3: Fetching EPSS scores from FIRST.org...")
allIDs := make([]string, 0, len(dictionary))
for id := range dictionary {
    allIDs = append(allIDs, id)
}
sort.Strings(allIDs)
epssScores := fetchEPSS(allIDs)
enriched := 0
for id, intel := range dictionary {
    if score, ok := epssScores[id]; ok {
        intel.EPSS = score
        dictionary[id] = intel
        enriched++
    }
}
log.Printf("  -> EPSS scores applied to %d/%d CVEs.", enriched, len(dictionary))
```

- [ ] **Step 5: Display EPSS in `dashboard.html` modal**

Find the modal rendering code (search for where `nvdLayer[cveId]` is read — around line 550–620). Add EPSS display after the CVSS score line:

```js
// After CVSS score display, add:
const epss = intel.e;
if (epss !== undefined) {
  const epssPercent = (epss * 100).toFixed(2);
  const epssColor = epss >= 0.7 ? 'text-red-400' : epss >= 0.3 ? 'text-yellow-400' : 'text-green-400';
  htmlChunks.push(`
    <div class="flex items-center justify-between py-1 border-b border-border">
      <span class="text-dim text-xs">EPSS Score</span>
      <span class="font-mono text-xs font-bold ${epssColor}">${epssPercent}% exploitation probability</span>
    </div>`);
}
```

- [ ] **Step 6: Build and test**

```bash
go build nvd_scraper.go
./nvd_scraper
```

Expected log output includes: `Phase 3: Fetching EPSS scores...` and `EPSS scores applied to N/M CVEs.`

Check a sample CVE has `e` field:
```bash
python3 -c "import json; d=json.load(open('data/nvd_intel.json')); print({k:v for k,v in list(d.items())[:3]})"
```

- [ ] **Step 7: Commit**

```bash
git add nvd_scraper.go dashboard.html data/nvd_intel*.json
git commit -m "feat(intel): add EPSS probability scores from FIRST.org to CVE intel"
```

---

## Task 3: Add CPE product mapping to `CVEIntel`

**Files:**
- Modify: `nvd_scraper.go` (add `Configurations` to NVD struct, extract products)
- No frontend changes needed in this task (products stored, UI comes in Plan B)

### Why
CPE (Common Platform Enumeration) data in NVD tells you *what product/vendor* a CVE affects. Currently missing — pentesters can't filter "show me CVEs affecting Apache products."

- [ ] **Step 1: Add NVD configuration structs**

```go
type Configuration struct {
	Nodes []ConfigNode `json:"nodes"`
}

type ConfigNode struct {
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type CPEMatch struct {
	Criteria   string `json:"criteria"`   // e.g. "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
	Vulnerable bool   `json:"vulnerable"`
}
```

Add `Configurations []Configuration` to `CVE2`:

```go
type CVE2 struct {
	ID                    string          `json:"id"`
	Published             string          `json:"published"`
	LastModified          string          `json:"lastModified"`
	VulnStatus            string          `json:"vulnStatus"`
	Descriptions          []LangValue     `json:"descriptions"`
	Metrics               Metrics2        `json:"metrics"`
	Weaknesses            []Weakness      `json:"weaknesses"`
	Configurations        []Configuration `json:"configurations"`
	CisaExploitAdd        string          `json:"cisaExploitAdd,omitempty"`
	CisaVulnerabilityName string          `json:"cisaVulnerabilityName,omitempty"`
}
```

- [ ] **Step 2: Add `Products` field to `CVEIntel`**

```go
type CVEIntel struct {
	Score     float64  `json:"s"`
	Severity  string   `json:"v"`
	Desc      string   `json:"d"`
	Vector    string   `json:"c,omitempty"`
	CWE       string   `json:"w,omitempty"`
	KEV       bool     `json:"k,omitempty"`
	Source    string   `json:"r,omitempty"`
	Published string   `json:"p,omitempty"`
	Status    string   `json:"u,omitempty"`
	EPSS      float64  `json:"e,omitempty"`
	Products  []string `json:"q,omitempty"` // "vendor:product" pairs
}
```

- [ ] **Step 3: Add `extractProducts` function**

CPE string format: `cpe:2.3:<part>:<vendor>:<product>:...`
We extract `vendor:product` for vulnerable=true entries, deduplicate.

```go
// extractProducts parses CPE criteria strings and returns unique "vendor:product" pairs.
func extractProducts(configs []Configuration) []string {
	seen := make(map[string]bool)
	var products []string
	// CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
	cpeRegex := regexp.MustCompile(`^cpe:2\.3:[aoh]:([^:]+):([^:]+):`)
	for _, config := range configs {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				m := cpeRegex.FindStringSubmatch(match.Criteria)
				if m == nil {
					continue
				}
				key := m[1] + ":" + m[2]
				if !seen[key] {
					seen[key] = true
					products = append(products, key)
				}
			}
		}
	}
	return products
}
```

- [ ] **Step 4: Call `extractProducts` in `extractIntel`**

At the end of `extractIntel`, before `return intel`:

```go
// CPE product mapping
intel.Products = extractProducts(cve.Configurations)
```

- [ ] **Step 5: Build and verify**

```bash
go build nvd_scraper.go
./nvd_scraper
```

Sample check — find a well-known CVE with CPE data:
```bash
python3 -c "
import json
d = json.load(open('data/nvd_intel.json'))
# log4shell
cve = d.get('CVE-2021-44228', {})
print('Products:', cve.get('q', 'MISSING'))
print('Score:', cve.get('s'))
"
```

Expected: `Products: ['apache:log4j']`

- [ ] **Step 6: Commit**

```bash
git add nvd_scraper.go data/nvd_intel*.json
git commit -m "feat(intel): add CPE product/vendor mapping to CVE intel entries"
```

---

## Task 4: Deferred CVE retry pass (age-gated)

**Files:**
- Modify: `nvd_scraper.go` — add Phase 2b targeting `Status == "Deferred"` entries older than 30 days

### Why
996 CVEs have `Status: "Deferred"` and `Score: 0`. NVD scores most CVEs within 2–4 weeks. A targeted retry on old Deferred entries cleans them up over time without wasting API budget on brand-new CVEs that simply aren't scored yet.

- [ ] **Step 1: Modify `collectMissingCVEs` to also return stale Deferred CVEs**

Replace the existing function:

```go
// collectMissingCVEs returns CVE IDs that are either:
// - absent from the dictionary, OR
// - have score == 0 (unscored), OR
// - have Status "Deferred" and were published > 30 days ago (eligible for re-fetch)
func collectMissingCVEs(dataDir string, dict map[string]CVEIntel) []string {
	validCVE  := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cutoff    := time.Now().AddDate(0, 0, -30)

	pattern := filepath.Join(dataDir, "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("[-] Glob error: %v", err)
		return nil
	}

	seen    := make(map[string]bool)
	var missing []string

	for _, f := range files {
		base := filepath.Base(f)
		if base == "nvd_intel.json" || strings.HasPrefix(base, "nvd_intel_") || base == "news.json" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var df DataFile
		if err := json.Unmarshal(raw, &df); err != nil {
			continue
		}
		for _, cve := range df.CVEs {
			id := cve.CVEID
			if !validCVE.MatchString(id) || seen[id] {
				continue
			}
			seen[id] = true
			existing, ok := dict[id]
			if !ok || existing.Score == 0 {
				missing = append(missing, id)
				continue
			}
			// Retry stale Deferred entries
			if existing.Status == "Deferred" && existing.Published != "" {
				pub, err := time.Parse("2006-01-02", existing.Published)
				if err == nil && pub.Before(cutoff) {
					missing = append(missing, id)
				}
			}
		}
	}
	return missing
}
```

- [ ] **Step 2: Build and run — check Deferred count drops**

```bash
go build nvd_scraper.go
./nvd_scraper 2>&1 | grep -E "Deferred|backfill|missing"
```

After run, check how many Deferred remain:
```bash
python3 -c "
import json
d = json.load(open('data/nvd_intel.json'))
deferred = sum(1 for v in d.values() if v.get('u') == 'Deferred')
print(f'Deferred remaining: {deferred}')
"
```

Expected: fewer than the pre-run 996.

- [ ] **Step 3: Commit**

```bash
git add nvd_scraper.go data/nvd_intel*.json
git commit -m "fix(intel): retry stale Deferred CVEs older than 30 days in backfill phase"
```

---

## Task 5: PoC quality signals on repository entries

**Files:**
- Modify: `cvemapping.go` — add `has_code`, `age_days` fields to repo output struct

### Why
0-star repos with no language set are often writeups, not exploits. Adding quality signals lets the frontend filter them without changing the scraper's keep-highest-starred dedup logic.

- [ ] **Step 1: Find the repo output struct in `cvemapping.go`**

Search for `GitHubRepository` or the struct used for JSON output. Read lines 30–80 to find it.

```bash
grep -n "type.*struct\|html_url\|stars\|language" cvemapping.go | head -30
```

- [ ] **Step 2: Add `HasCode bool` and `AgeDays int` to the repository output struct**

Find the struct that maps to the JSON output (has fields like `html_url`, `stars`, `language`). Add:

```go
HasCode bool   `json:"has_code"` // true if GitHub reports a primary language
AgeDays int    `json:"age_days"` // days since repo creation at scrape time
```

- [ ] **Step 3: Populate `has_code` and `age_days` during repo processing**

Find where repo fields are assigned (likely in a loop that calls the GitHub API). Add:

```go
repo.HasCode = r.Language != ""  // GitHub sets Language to primary language if code exists
if !r.CreatedAt.IsZero() {
    repo.AgeDays = int(time.Since(r.CreatedAt).Hours() / 24)
}
```

Note: `CreatedAt` must be parsed from GitHub's `created_at` field. Check if `GitHubRepository` already has it — if not, add:

```go
CreatedAt time.Time `json:"-"`
```

And parse it from the raw response:
```go
type GitHubSearchItem struct {
    // ... existing fields ...
    CreatedAt string `json:"created_at"`
    Language  string `json:"language"`
}
```

Then during mapping:
```go
if t, err := time.Parse(time.RFC3339, item.CreatedAt); err == nil {
    repo.CreatedAt = t
}
```

- [ ] **Step 4: Build and verify**

```bash
go build cvemapping.go
echo "CVE-2025-" | ./cvemapping -github-token "$GITHUB_TOKEN" -export-json -year 2025 -page all
python3 -c "
import json
d = json.load(open('data/2025.json'))
sample = d['cves'][0]['repositories'][0]
print('has_code:', sample.get('has_code'))
print('age_days:', sample.get('age_days'))
"
```

Expected: `has_code: True` and `age_days: <integer>` present.

- [ ] **Step 5: Commit**

```bash
git add cvemapping.go data/2025.json data/2026.json
git commit -m "feat(scraper): add has_code and age_days quality signals to repository entries"
```

---

## Task 6: Scraper health checks in GitHub Actions

**Files:**
- Modify: `.github/workflows/scrape.yml`
- Modify: `.github/workflows/news.yml`

### Why
If GitHub token expires, NVD goes down, or the scraper produces empty output, the workflow currently succeeds silently. Adding a validation step catches failures before bad data commits.

- [ ] **Step 1: Add validation step to `scrape.yml`**

After the `Build and Execute Scraper Engines` step, add a new step:

```yaml
      - name: Validate Output Data
        run: |
          echo "Validating CVE data output..."
          YEAR=$(date +%Y)
          
          # Check current year file exists and has minimum CVE count
          YEAR_FILE="data/${YEAR}.json"
          if [ ! -f "$YEAR_FILE" ]; then
            echo "ERROR: $YEAR_FILE not found — scraper may have failed"
            exit 1
          fi
          
          CVE_COUNT=$(python3 -c "import json,sys; d=json.load(open('$YEAR_FILE')); print(len(d['cves']))" 2>/dev/null || echo 0)
          echo "CVEs in $YEAR_FILE: $CVE_COUNT"
          if [ "$CVE_COUNT" -lt 100 ]; then
            echo "ERROR: Only $CVE_COUNT CVEs found in $YEAR_FILE — expected at least 100. Aborting commit."
            exit 1
          fi
          
          # Check nvd_intel exists and is non-empty
          NVD_FILE="data/nvd_intel.json"
          if [ ! -f "$NVD_FILE" ]; then
            echo "ERROR: $NVD_FILE not found"
            exit 1
          fi
          NVD_COUNT=$(python3 -c "import json; d=json.load(open('$NVD_FILE')); print(len(d))" 2>/dev/null || echo 0)
          echo "Signatures in nvd_intel.json: $NVD_COUNT"
          if [ "$NVD_COUNT" -lt 10000 ]; then
            echo "ERROR: nvd_intel.json has only $NVD_COUNT entries — something went wrong"
            exit 1
          fi
          
          echo "Validation passed."
```

- [ ] **Step 2: Add validation step to `news.yml`**

After the `Build and Execute News Scraper` step, add:

```yaml
      - name: Validate News Output
        run: |
          NEWS_FILE="data/news.json"
          if [ ! -f "$NEWS_FILE" ]; then
            echo "ERROR: $NEWS_FILE not found"
            exit 1
          fi
          ARTICLE_COUNT=$(python3 -c "import json; d=json.load(open('$NEWS_FILE')); print(len(d.get('articles', [])))" 2>/dev/null || echo 0)
          echo "Articles in news.json: $ARTICLE_COUNT"
          if [ "$ARTICLE_COUNT" -lt 10 ]; then
            echo "ERROR: Only $ARTICLE_COUNT articles — RSS feeds may be unreachable"
            exit 1
          fi
          echo "Validation passed."
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/scrape.yml .github/workflows/news.yml
git commit -m "feat(ci): add output validation steps to scrape and news workflows"
```

---

## Task 7: Orphan data branch — stop repo bloat

**Files:**
- Modify: `.github/workflows/scrape.yml` (push data to orphan `data` branch)
- Modify: `.github/workflows/news.yml` (same)
- Modify: `dashboard.html`, `news.html`, `docs.html` (update data URLs to use raw GitHub content from `data` branch)

### Why
276MB and growing. Every 6h data commit adds full JSON diffs to the main branch pack history. Orphan branch with shallow commits keeps data history separate — main stays lightweight code history, `data` branch retains a short rolling window of JSON history.

- [ ] **Step 1: Create the orphan data branch (one-time, run locally)**

```bash
# From the repo root
git checkout --orphan data
git rm -rf .
echo "# CVE Map Data Branch" > README.md
git add README.md
git commit -m "init: orphan data branch"
git push origin data
git checkout feature/scraper-sources-upgrade  # or your current branch
```

- [ ] **Step 2: Update `scrape.yml` to push data to the `data` branch**

Replace the `Commit & Push New Datasets` step:

```yaml
      - name: Commit & Push to Data Branch
        run: |
          git config --global user.name "Nikhil Yadav (Bot)"
          git config --global user.email "yadavnikhil17102004@gmail.com"
          
          # Fetch the data branch
          git fetch origin data
          git checkout data
          
          # Copy new JSON files in
          cp -r /home/runner/work/CVE_Map_hehe/CVE_Map_hehe/data/*.json ./data/ 2>/dev/null || true
          
          # Stage and commit with shallow history intent
          git add data/
          if ! git diff-index --quiet HEAD; then
            git commit -m "chore(data): Automated upstream exploit sync $(date -u +%Y-%m-%dT%H:%M:%SZ) [skip ci]"
            git push origin data
          else
            echo "No changes. Skipping push."
          fi
          
          # Return to original branch
          git checkout -
```

Note: The workflow `checkout@v4` step checks out main. The data files are written to the runner filesystem. We then switch to the `data` branch, copy the files, commit there.

- [ ] **Step 3: Update `news.yml` similarly**

Replace the commit step:

```yaml
      - name: Commit & Push to Data Branch
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action Bot"
          git fetch origin data
          git checkout data
          cp /home/runner/work/CVE_Map_hehe/CVE_Map_hehe/data/news.json ./data/news.json
          git add data/news.json
          git diff --quiet && git diff --staged --quiet || git commit -m "data: hourly live news feed $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push origin data
          git checkout -
```

- [ ] **Step 4: Update data URLs in frontend HTML files**

GitHub raw content URL for the `data` branch:
`https://raw.githubusercontent.com/yadavnikhil17102004/CVE_Map_hehe/data/data/{file}`

In `dashboard.html`, replace all `fetch('data/` with `fetch('https://raw.githubusercontent.com/yadavnikhil17102004/CVE_Map_hehe/data/data/`:

```bash
grep -n "fetch('data/" dashboard.html
# Then update each one
```

In `news.html` and `docs.html`, update any hardcoded data paths similarly.

- [ ] **Step 5: Verify locally that the dashboard still loads**

```bash
./start.sh
# Open dashboard — data should load from raw.githubusercontent.com URLs
# Check browser network tab — requests go to raw.githubusercontent.com/...
```

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/scrape.yml .github/workflows/news.yml dashboard.html news.html docs.html
git commit -m "feat(infra): move data commits to orphan data branch, reduce main repo bloat"
```

---

## Self-Review

**Spec coverage:**
- [x] nvd_intel.json split by year → Task 1
- [x] EPSS scores → Task 2
- [x] CPE product mapping → Task 3
- [x] Deferred CVE retry → Task 4
- [x] PoC quality signals → Task 5
- [x] Scraper health checks → Task 6
- [x] Orphan data branch → Task 7

**Dependency order:** Tasks 1–5 are independent. Task 6 (health checks) should come after 1–5 since thresholds assume enriched data. Task 7 (data branch) is last since it changes where data lives — do this after other data changes are validated.

**Type consistency:** `CVEIntel` fields added across tasks 2, 3 are additive — no conflicts. `q` (products) and `e` (epss) are new keys that don't collide with existing single-char keys (`s`, `v`, `d`, `c`, `w`, `k`, `r`, `p`, `u`).
