package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// ============================================================
// NVD 2.0 API — Response Structs
// ============================================================

type NVD2Response struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVE CVE2 `json:"cve"`
}

type CVE2 struct {
	ID                    string      `json:"id"`
	Published             string      `json:"published"`
	LastModified          string      `json:"lastModified"`
	VulnStatus            string      `json:"vulnStatus"`
	Descriptions          []LangValue `json:"descriptions"`
	Metrics               Metrics2    `json:"metrics"`
	Weaknesses            []Weakness  `json:"weaknesses"`
	CisaExploitAdd        string      `json:"cisaExploitAdd,omitempty"`
	CisaVulnerabilityName string      `json:"cisaVulnerabilityName,omitempty"`
}

type LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics2 struct {
	CVSSMetricV31 []CVSSMetricEntry   `json:"cvssMetricV31"`
	CVSSMetricV30 []CVSSMetricEntry   `json:"cvssMetricV30"`
	CVSSMetricV2  []CVSSMetricV2Entry `json:"cvssMetricV2"`
}

type CVSSMetricEntry struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"` // "Primary" (NIST) or "Secondary" (CNA)
	CVSSData CVSSData `json:"cvssData"`
}

type CVSSData struct {
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type CVSSMetricV2Entry struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

type Weakness struct {
	Source      string      `json:"source"`
	Type        string      `json:"type"`
	Description []LangValue `json:"description"`
}

// ============================================================
// Our compact output format — what lands in nvd_intel.json
// ============================================================

type CVEIntel struct {
	Score     float64 `json:"s"`            // CVSS base score
	Severity  string  `json:"v"`            // CRITICAL / HIGH / MEDIUM / LOW
	Desc      string  `json:"d"`            // English description
	Vector    string  `json:"c,omitempty"`  // CVSS vector string
	CWE       string  `json:"w,omitempty"`  // Primary CWE (e.g. CWE-502)
	KEV       bool    `json:"k,omitempty"`  // true if in CISA Known Exploited Vulnerabilities
	Source    string  `json:"r,omitempty"`  // "NIST" or "CNA"
	Published string  `json:"p,omitempty"`  // YYYY-MM-DD
	Status    string  `json:"u,omitempty"`  // vulnStatus
}

// ============================================================
// Minimal data file structs (to read our own JSON)
// ============================================================

type DataFile struct {
	CVEs []struct {
		CVEID string `json:"cve_id"`
	} `json:"cves"`
}

// ============================================================
// Main
// ============================================================

func main() {
	start := time.Now()
	log.Println("[+] NVD Intelligence Engine v2.1 — Booting...")

	apiKey := os.Getenv("NVD_API_KEY")
	if apiKey != "" {
		log.Println("[i] NVD_API_KEY detected — elevated rate limit (50 req/30s).")
	} else {
		log.Println("[i] No NVD_API_KEY — unauthenticated rate (5 req/30s). Add key to speed up.")
	}

	os.MkdirAll("data", 0755)
	intelFile := filepath.Join("data", "nvd_intel.json")

	// Load existing dictionary (accumulate across runs)
	dictionary := make(map[string]CVEIntel)
	if raw, err := os.ReadFile(intelFile); err == nil {
		if err := json.Unmarshal(raw, &dictionary); err != nil {
			log.Printf("[-] Warning: existing intel file unparseable — rebuilding fresh.")
		} else {
			log.Printf("[i] Loaded %d existing signatures.", len(dictionary))
		}
	}

	// ── Phase 1: 180-day modification window ─────────────────
	// Catches new CVEs and updated scores on existing ones.
	log.Println("[+] Phase 1: Fetching last 180 days from NVD (new/modified CVEs)...")
	now := time.Now().UTC()
	windows := []struct{ start, end time.Time }{
		{now.AddDate(0, 0, -90), now.AddDate(0, 0, -45)},
		{now.AddDate(0, 0, -45), now},
	}
	for i, w := range windows {
		log.Printf("  Window %d/2: %s → %s", i+1,
			w.start.Format("2006-01-02"), w.end.Format("2006-01-02"))
		if err := fetchWindow(w.start, w.end, dictionary, apiKey); err != nil {
			log.Printf("  [-] Window %d failed: %v", i+1, err)
		}
	}

	// ── Phase 2: Targeted backfill ───────────────────────────
	// Read all data/*.json, find CVE IDs that are missing or
	// have score=0 (UNSCORED), fetch them individually from NVD.
	log.Println("[+] Phase 2: Targeted backfill for unscored CVEs in data files...")
	missing := collectMissingCVEs("data", dictionary)
	log.Printf("  Found %d CVEs to backfill (missing or unscored).", len(missing))
	if len(missing) > 0 {
		fetchTargeted(missing, dictionary, apiKey)
	}

	// ── Write output ─────────────────────────────────────────
	out, err := json.Marshal(dictionary)
	if err != nil {
		log.Fatalf("[-] FATAL: Failed to serialize dictionary: %v", err)
	}
	if err := os.WriteFile(intelFile, out, 0644); err != nil {
		log.Fatalf("[-] FATAL: Failed to write %s: %v", intelFile, err)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[+] Done in %s. Dictionary: %d signatures → %s (%.1f KB)",
		elapsed, len(dictionary), intelFile, float64(len(out))/1024.0)
}

// ============================================================
// Phase 1: Fetch a time window with full pagination
// ============================================================

func fetchWindow(from, to time.Time, dict map[string]CVEIntel, apiKey string) error {
	const pageSize = 2000
	startIdx := 0
	total := -1
	cveIDRegex := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	added := 0

	for total == -1 || startIdx < total {
		url := fmt.Sprintf(
			"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=%s&lastModEndDate=%s&startIndex=%d&resultsPerPage=%d",
			from.Format("2006-01-02T15:04:05.000"),
			to.Format("2006-01-02T15:04:05.000"),
			startIdx, pageSize,
		)
		resp, err := nvdGet(url, apiKey)
		if err != nil {
			return fmt.Errorf("GET failed at startIndex=%d: %w", startIdx, err)
		}
		if total == -1 {
			total = resp.TotalResults
			log.Printf("  -> %d CVEs in window.", total)
		}
		for _, vuln := range resp.Vulnerabilities {
			cve := vuln.CVE
			if !cveIDRegex.MatchString(cve.ID) {
				continue
			}
			dict[cve.ID] = extractIntel(cve)
			added++
		}
		startIdx += len(resp.Vulnerabilities)
		if len(resp.Vulnerabilities) == 0 {
			break
		}
		rateSleep(apiKey)
	}
	log.Printf("  -> Updated %d signatures.", added)
	return nil
}

// ============================================================
// Phase 2: Collect missing/unscored CVE IDs from data files
// ============================================================

// collectMissingCVEs scans all data/*.json files for CVE IDs that are
// either absent from the dictionary or have score == 0 (UNSCORED).
// Returns at most maxPerRun entries to keep each scraper cycle fast.
func collectMissingCVEs(dataDir string, dict map[string]CVEIntel) []string {
	const maxPerRun = 200 // drain gradually — prevents 60+ min backfill runs

	validCVE := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`) // strict format only

	pattern := filepath.Join(dataDir, "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("[-] Glob error: %v", err)
		return nil
	}

	seen := make(map[string]bool)
	var missing []string

	for _, f := range files {
		if filepath.Base(f) == "nvd_intel.json" {
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
			if !validCVE.MatchString(id) {
				continue // skip OTHER-XXXX, GHSA-*, etc.
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			existing, ok := dict[id]
			if !ok || existing.Score == 0 {
				missing = append(missing, id)
				if len(missing) >= maxPerRun {
					log.Printf("  [i] Capped at %d CVEs/run. Remainder will be fetched in subsequent runs.", maxPerRun)
					return missing
				}
			}
		}
	}
	return missing
}

// ============================================================
// Phase 2: Fetch individual CVEs by ID
// ============================================================

func fetchTargeted(cveIDs []string, dict map[string]CVEIntel, apiKey string) {
	fetched := 0
	failed := 0

	for i, id := range cveIDs {
		url := fmt.Sprintf(
			"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", id)

		resp, err := nvdGet(url, apiKey)
		if err != nil {
			log.Printf("  [-] Failed to fetch %s: %v", id, err)
			failed++
			rateSleep(apiKey) // still sleep on error to respect rate limit
			continue
		}

		if len(resp.Vulnerabilities) > 0 {
			dict[id] = extractIntel(resp.Vulnerabilities[0].CVE)
			fetched++
		}

		// Progress log every 50
		if (i+1)%50 == 0 {
			log.Printf("  -> Backfilled %d/%d CVEs so far...", i+1, len(cveIDs))
		}

		rateSleep(apiKey)
	}

	log.Printf("  -> Backfill complete: %d fetched, %d failed.", fetched, failed)
}

// ============================================================
// HTTP helper
// ============================================================

func nvdGet(url, apiKey string) (*NVD2Response, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		// Rate limited — back off and retry once
		time.Sleep(35 * time.Second)
		return nvdGet(url, apiKey)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result NVD2Response
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}
	return &result, nil
}

// rateSleep respects NVD rate limits:
// Authenticated:   50 req/30s → sleep 650ms
// Unauthenticated: 5 req/30s  → sleep 6500ms
func rateSleep(apiKey string) {
	if apiKey != "" {
		time.Sleep(650 * time.Millisecond)
	} else {
		time.Sleep(6500 * time.Millisecond)
	}
}

// ============================================================
// Extract intel from a CVE2 entry
// ============================================================

func extractIntel(cve CVE2) CVEIntel {
	intel := CVEIntel{}

	// Description
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			intel.Desc = d.Value
			break
		}
	}
	if intel.Desc == "" {
		intel.Desc = "No description available."
	}

	// CVSS Score — priority: NIST Primary > CNA Secondary > v2 fallback
	scoreSet := false
	for _, m := range append(cve.Metrics.CVSSMetricV31, cve.Metrics.CVSSMetricV30...) {
		if m.Type == "Primary" && m.CVSSData.BaseScore > 0 {
			intel.Score    = m.CVSSData.BaseScore
			intel.Severity = m.CVSSData.BaseSeverity
			intel.Vector   = m.CVSSData.VectorString
			intel.Source   = "NIST"
			scoreSet = true
			break
		}
	}
	if !scoreSet {
		for _, m := range append(cve.Metrics.CVSSMetricV31, cve.Metrics.CVSSMetricV30...) {
			if m.Type == "Secondary" && m.CVSSData.BaseScore > 0 {
				intel.Score    = m.CVSSData.BaseScore
				intel.Severity = m.CVSSData.BaseSeverity
				intel.Vector   = m.CVSSData.VectorString
				intel.Source   = "CNA"
				scoreSet = true
				break
			}
		}
	}
	if !scoreSet {
		for _, m := range cve.Metrics.CVSSMetricV2 {
			if m.CVSSData.BaseScore > 0 {
				intel.Score    = m.CVSSData.BaseScore
				intel.Severity = m.BaseSeverity
				intel.Vector   = m.CVSSData.VectorString
				intel.Source   = "CVSSv2"
				break
			}
		}
	}

	// CWE — prefer NIST Primary
	for _, w := range cve.Weaknesses {
		if w.Type == "Primary" {
			for _, d := range w.Description {
				if d.Lang == "en" && d.Value != "NVD-CWE-Other" && d.Value != "NVD-CWE-noinfo" {
					intel.CWE = d.Value
					break
				}
			}
			if intel.CWE != "" {
				break
			}
		}
	}
	if intel.CWE == "" {
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" && d.Value != "NVD-CWE-Other" && d.Value != "NVD-CWE-noinfo" {
					intel.CWE = d.Value
					break
				}
			}
			if intel.CWE != "" {
				break
			}
		}
	}

	// CISA KEV
	intel.KEV = cve.CisaExploitAdd != ""

	// Published date
	if len(cve.Published) >= 10 {
		intel.Published = cve.Published[:10]
	}

	// Status
	intel.Status = cve.VulnStatus

	return intel
}
