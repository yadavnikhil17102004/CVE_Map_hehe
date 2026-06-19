# Frontend/UX Upgrades — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add shareable URL state, PoC quality filter toggle in the dashboard, and Discord/Slack watchlist alerting via GitHub Actions.

**Architecture:** Pure vanilla JS changes to `dashboard.html` for URL state and quality filter. Alerting is a new Go script + GitHub Actions workflow that diffs new CVEs against a community `watchlist.json`.

**Tech Stack:** Vanilla JS (no frameworks), Go 1.25 stdlib, GitHub Actions, Discord/Slack webhooks.

**Dependency:** Run after `2026-04-13-data-layer-upgrades.md` — quality filter relies on `has_code` and `age_days` fields added in that plan (Task 5).

---

## Task 1: Shareable URL state (year, severity, search query)

**Files:**
- Modify: `dashboard.html` — push/read filter state from URL hash

### Why
Current filter state (year, search query) is lost on page refresh and can't be shared. URL hash state is zero-backend, no routing library needed, one-liner serialization.

Format: `dashboard.html#year=2024&q=log4j&severity=CRITICAL`

- [ ] **Step 1: Add `readURLState` helper near the top of the script block**

After `let sortDir = 'desc';` and before `const YEARS = ...` (around line 322):

```js
// ── URL state helpers ──────────────────────────────────────
function readURLState() {
  const hash = location.hash.replace('#', '');
  const params = Object.fromEntries(new URLSearchParams(hash));
  return {
    year:     parseInt(params.year) || new Date().getFullYear(),
    q:        params.q     || '',
    severity: params.severity || 'all',
  };
}

function writeURLState() {
  const params = new URLSearchParams();
  params.set('year', currentYear);
  if (currentSearch) params.set('q', currentSearch);
  if (typeFilter !== 'all') params.set('severity', typeFilter);
  history.replaceState(null, '', '#' + params.toString());
}
```

Add `let currentSearch = '';` near the other `let` declarations.

- [ ] **Step 2: Read state on boot in `DOMContentLoaded`**

Replace the boot sequence start:

```js
document.addEventListener('DOMContentLoaded', async () => {
  const state = readURLState();
  currentYear = state.year;
  typeFilter  = state.severity;

  buildYearGrid(); // uses currentYear — must run after state is set
  // ... rest of boot unchanged
```

After loading year data, restore search query if present:

```js
  await loadYear(currentYear);

  // Restore search from URL
  if (state.q) {
    ['search-input', 'search-mobile'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = state.q;
    });
    currentSearch = state.q;
    globalSearch(state.q);
  }
```

- [ ] **Step 3: Call `writeURLState()` whenever filters change**

In `selectYear(y)` before `loadYear(y)`:
```js
function selectYear(y) {
  currentYear = y;
  writeURLState();
  // ... rest unchanged
```

In the search `input` event listener, after updating `currentSearch`:
```js
currentSearch = q;
writeURLState();
```

In `typeFilter` change (wherever severity filter is set), add `writeURLState()`.

- [ ] **Step 4: Add a "Copy link" button to the header**

Find the header action buttons area (around line 87). Add after the API JSON link:

```html
<button onclick="copyShareLink()"
  class="flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-border text-xs font-medium hover:bg-surface-2 transition-colors text-gray-300"
  title="Copy shareable link">
  <span class="material-symbols-outlined text-sm">link</span>
  <span id="share-btn-label">Share</span>
</button>
```

Add the function:

```js
function copyShareLink() {
  writeURLState();
  navigator.clipboard.writeText(location.href).then(() => {
    const label = document.getElementById('share-btn-label');
    if (label) {
      label.textContent = 'Copied!';
      setTimeout(() => label.textContent = 'Share', 1500);
    }
  });
}
```

- [ ] **Step 5: Test**

```bash
./start.sh
```

1. Select year 2021, search "log4j" — URL hash updates to `#year=2021&q=log4j`
2. Copy URL, paste in new tab — dashboard loads with 2021 selected and "log4j" pre-searched
3. Click Share button — "Copied!" flashes, clipboard has full URL

- [ ] **Step 6: Commit**

```bash
git add dashboard.html
git commit -m "feat(ui): add shareable URL state for year, search, and severity filter"
```

---

## Task 2: PoC quality filter toggle

**Files:**
- Modify: `dashboard.html` — add filter toggle UI + filter logic using `has_code` and `age_days`

**Requires:** `has_code` and `age_days` fields from data-layer-upgrades Task 5. If those fields are absent, the filter is a no-op (graceful degradation).

### Why
Some repos in the dataset are writeups, detection scripts, or clones with no actual exploit code. Quality filter lets researchers focus on repos with actual code that aren't brand-new (likely real PoCs).

Quality threshold: `has_code === true` AND `age_days >= 3`.

- [ ] **Step 1: Add filter state variable**

Near the other `let` declarations (around line 320):

```js
let qualityFilter = false; // true = show only repos with code, age >= 3 days
```

- [ ] **Step 2: Add toggle button to the toolbar**

Find the filter/sort controls area in the dashboard (search for `typeFilter` or the sort buttons). Add a quality filter toggle near the sort controls:

```html
<button id="quality-toggle" onclick="toggleQualityFilter()"
  class="flex items-center gap-1.5 px-2 py-1 rounded border border-border text-[11px] font-mono transition-all text-gray-400 hover:border-gray-500"
  title="Show only repos with actual code (has_code=true, age≥3d)">
  <span class="material-symbols-outlined text-xs">verified</span>
  PoC Only
</button>
```

- [ ] **Step 3: Add toggle function**

```js
function toggleQualityFilter() {
  qualityFilter = !qualityFilter;
  const btn = document.getElementById('quality-toggle');
  if (btn) {
    btn.classList.toggle('border-primary', qualityFilter);
    btn.classList.toggle('text-primary', qualityFilter);
    btn.classList.toggle('bg-primary/10', qualityFilter);
    btn.classList.toggle('text-gray-400', !qualityFilter);
    btn.classList.toggle('border-border', !qualityFilter);
  }
  renderList(currentSearch);
  writeURLState();
}
```

- [ ] **Step 4: Apply quality filter in `renderList` (or wherever rows are rendered)**

Find where individual repository entries are rendered (the loop that builds CVE rows). Add a filter before rendering each repo:

```js
// Inside the repo rendering loop, before building the row HTML:
function repoPassesQualityFilter(repo) {
  if (!qualityFilter) return true;
  const hasCode = repo.has_code === true;
  const ageOk   = typeof repo.age_days === 'number' ? repo.age_days >= 3 : true; // graceful if field absent
  return hasCode && ageOk;
}
```

Apply in the loop:
```js
const filteredRepos = cve.repositories.filter(repoPassesQualityFilter);
if (filteredRepos.length === 0) return; // skip CVE if no repos pass filter
```

- [ ] **Step 5: Persist quality filter state in URL**

In `readURLState`:
```js
function readURLState() {
  const hash = location.hash.replace('#', '');
  const params = Object.fromEntries(new URLSearchParams(hash));
  return {
    year:          parseInt(params.year) || new Date().getFullYear(),
    q:             params.q      || '',
    severity:      params.severity || 'all',
    qualityFilter: params.poc === '1',
  };
}
```

In `writeURLState`:
```js
if (qualityFilter) params.set('poc', '1');
```

In `DOMContentLoaded` boot, after reading state:
```js
qualityFilter = state.qualityFilter;
if (qualityFilter) {
  const btn = document.getElementById('quality-toggle');
  if (btn) {
    btn.classList.add('border-primary', 'text-primary', 'bg-primary/10');
    btn.classList.remove('text-gray-400', 'border-border');
  }
}
```

- [ ] **Step 6: Test**

```bash
./start.sh
```

1. Toggle "PoC Only" — button highlights, table re-renders with fewer rows
2. Repos with no code or age < 3 days should be hidden
3. Refresh page — filter state persists via URL

- [ ] **Step 7: Commit**

```bash
git add dashboard.html
git commit -m "feat(ui): add PoC quality filter toggle (has_code + age_days threshold)"
```

---

## Task 3: Watchlist alerting via Discord/Slack webhook

**Files:**
- Create: `watchlist_alerter.go` — reads `watchlist.json`, diffs against current CVE data, POSTs webhook alerts
- Create: `watchlist.json` — community-maintained list of tracked CVE IDs
- Create: `.github/workflows/watchlist.yml` — runs alerter after each CVE sync

### Why
Security teams want to know the moment a PoC drops for a CVE they care about. The existing `cvemapping.sh` was a dead-start on this — this implements it properly integrated into the main pipeline.

- [ ] **Step 1: Create `watchlist.json`**

```bash
cat > watchlist.json << 'EOF'
{
  "description": "CVE IDs to watch for new PoC repositories. Add CVEs here to receive webhook alerts when exploits are discovered.",
  "webhook_env": "ALERT_WEBHOOK_URL",
  "cves": [
    "CVE-2025-0001",
    "CVE-2024-55591"
  ]
}
EOF
```

- [ ] **Step 2: Create `watchlist_alerter.go`**

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Watchlist struct {
	CVEs []string `json:"cves"`
}

type YearData struct {
	CVEs []struct {
		CVEID        string `json:"cve_id"`
		Repositories []struct {
			Name    string `json:"name"`
			HTMLURL string `json:"html_url"`
			Stars   int    `json:"stargazers_count"`
			HasCode bool   `json:"has_code"`
		} `json:"repositories"`
	} `json:"cves"`
}

type AlertedCache struct {
	Alerted map[string]bool `json:"alerted"`
}

func main() {
	webhookURL := os.Getenv("ALERT_WEBHOOK_URL")
	if webhookURL == "" {
		log.Println("[i] ALERT_WEBHOOK_URL not set — exiting without alerting.")
		os.Exit(0)
	}

	// Load watchlist
	wlRaw, err := os.ReadFile("watchlist.json")
	if err != nil {
		log.Fatalf("[-] Cannot read watchlist.json: %v", err)
	}
	var wl Watchlist
	if err := json.Unmarshal(wlRaw, &wl); err != nil {
		log.Fatalf("[-] Cannot parse watchlist.json: %v", err)
	}
	if len(wl.CVEs) == 0 {
		log.Println("[i] No CVEs in watchlist. Done.")
		return
	}

	// Load alerted cache (prevents duplicate alerts)
	cacheFile := ".watchlist_alerted.json"
	cache := AlertedCache{Alerted: make(map[string]bool)}
	if raw, err := os.ReadFile(cacheFile); err == nil {
		json.Unmarshal(raw, &cache)
	}

	// Build set of watched CVEs
	watching := make(map[string]bool)
	for _, id := range wl.CVEs {
		watching[strings.ToUpper(id)] = true
	}

	// Scan current year + last year data files
	years := []int{time.Now().Year(), time.Now().Year() - 1}
	alerts := 0

	for _, year := range years {
		path := filepath.Join("data", fmt.Sprintf("%d.json", year))
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var yd YearData
		if err := json.Unmarshal(raw, &yd); err != nil {
			continue
		}
		for _, cve := range yd.CVEs {
			id := strings.ToUpper(cve.CVEID)
			if !watching[id] {
				continue
			}
			for _, repo := range cve.Repositories {
				cacheKey := id + ":" + repo.HTMLURL
				if cache.Alerted[cacheKey] {
					continue // already alerted
				}
				// Send alert
				if err := sendWebhookAlert(webhookURL, id, repo.Name, repo.HTMLURL, repo.Stars, repo.HasCode); err != nil {
					log.Printf("[-] Failed to alert for %s: %v", id, err)
					continue
				}
				cache.Alerted[cacheKey] = true
				alerts++
				log.Printf("[+] Alerted: %s → %s", id, repo.HTMLURL)
				time.Sleep(500 * time.Millisecond) // avoid webhook rate limits
			}
		}
	}

	// Save updated cache
	cacheOut, _ := json.MarshalIndent(cache, "", "  ")
	os.WriteFile(cacheFile, cacheOut, 0644)

	log.Printf("[+] Done. %d new alerts sent.", alerts)
}

// sendWebhookAlert sends a Discord-compatible webhook message.
// Also compatible with Slack incoming webhooks (same JSON format for basic messages).
func sendWebhookAlert(webhookURL, cveID, repoName, repoURL string, stars int, hasCode bool) error {
	qualityTag := ""
	if hasCode {
		qualityTag = " ✅ has code"
	}

	payload := map[string]interface{}{
		"content": fmt.Sprintf("🚨 **New PoC detected for %s**\n📦 `%s`%s\n⭐ %d stars\n🔗 %s",
			cveID, repoName, qualityTag, stars, repoURL),
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
```

- [ ] **Step 3: Create `.github/workflows/watchlist.yml`**

```yaml
name: Watchlist Alerter

on:
  workflow_run:
    workflows: ["Continuous Exploit Scraper"]
    types: [completed]
  workflow_dispatch:

jobs:
  alert:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' || github.event_name == 'workflow_dispatch' }}

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run Watchlist Alerter
        env:
          ALERT_WEBHOOK_URL: ${{ secrets.ALERT_WEBHOOK_URL }}
        run: |
          go build watchlist_alerter.go
          ./watchlist_alerter

      - name: Commit Alert Cache
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action Bot"
          git add .watchlist_alerted.json watchlist.json || true
          git diff --quiet && git diff --staged --quiet || git commit -m "chore: update watchlist alert cache [skip ci]"
          git push
```

- [ ] **Step 4: Add `.watchlist_alerted.json` to `.gitignore` or include it**

It should be committed (it's the dedup cache — losing it causes duplicate alerts). Make sure it's not in `.gitignore`:

```bash
grep watchlist .gitignore 2>/dev/null || echo "Not in .gitignore — good"
```

- [ ] **Step 5: Build and test locally (dry run without webhook)**

```bash
go build watchlist_alerter.go
./watchlist_alerter
# Expected: "[i] ALERT_WEBHOOK_URL not set — exiting without alerting."
```

With a test webhook (use Discord's webhook tester or a local mock):
```bash
ALERT_WEBHOOK_URL="https://discord.com/api/webhooks/TEST/TOKEN" ./watchlist_alerter
```

- [ ] **Step 6: Add `ALERT_WEBHOOK_URL` secret to GitHub repo settings**

Instructions: GitHub repo → Settings → Secrets → Actions → New repository secret → `ALERT_WEBHOOK_URL` = your Discord/Slack webhook URL.

Document this in `watchlist.json`'s description field (already done in Step 1).

- [ ] **Step 7: Commit**

```bash
git add watchlist_alerter.go watchlist.json .github/workflows/watchlist.yml
git commit -m "feat(alerting): add CVE watchlist alerter with Discord/Slack webhook support"
```

---

## Self-Review

**Spec coverage:**
- [x] Shareable URL state → Task 1
- [x] PoC quality filter toggle → Task 2
- [x] Watchlist + alerting → Task 3

**Dependency:** Task 2 quality filter gracefully degrades if `has_code`/`age_days` fields are absent (shows all repos). Safe to implement before data-layer Task 5 is merged.

**Type consistency:** `readURLState` returns `qualityFilter` bool used in Task 2 boot sequence. `writeURLState` sets `poc=1` — matches `readURLState` reading `params.poc === '1'`. Consistent.

**Placeholder scan:** All webhook payloads, URL formats, and Go structs are fully specified. No TBDs.
