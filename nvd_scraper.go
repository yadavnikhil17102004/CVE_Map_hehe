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
	ResultsPerPage int              `json:"resultsPerPage"`
	StartIndex     int              `json:"startIndex"`
	TotalResults   int              `json:"totalResults"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVE CVE2 `json:"cve"`
}

type CVE2 struct {
	ID               string        `json:"id"`
	Published        string        `json:"published"`
	LastModified     string        `json:"lastModified"`
	VulnStatus       string        `json:"vulnStatus"`
	Descriptions     []LangValue   `json:"descriptions"`
	Metrics          Metrics2      `json:"metrics"`
	Weaknesses       []Weakness    `json:"weaknesses"`
	References       []Reference   `json:"references"`
	// CISA KEV fields — only populated if in the catalog
	CisaExploitAdd        string `json:"cisaExploitAdd,omitempty"`
	CisaActionDue         string `json:"cisaActionDue,omitempty"`
	CisaVulnerabilityName string `json:"cisaVulnerabilityName,omitempty"`
}

type LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics2 struct {
	CVSSMetricV31 []CVSSMetricEntry `json:"cvssMetricV31"`
	CVSSMetricV30 []CVSSMetricEntry `json:"cvssMetricV30"`
	CVSSMetricV2  []CVSSMetricV2Entry `json:"cvssMetricV2"`
}

type CVSSMetricEntry struct {
	Source string   `json:"source"`
	Type   string   `json:"type"` // "Primary" (NIST) or "Secondary" (CNA)
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
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []LangValue  `json:"description"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// ============================================================
// Our compact output format — what lands in nvd_intel.json
// ============================================================

type CVEIntel struct {
	Score    float64 `json:"s"`            // CVSS base score
	Severity string  `json:"v"`            // CRITICAL / HIGH / MEDIUM / LOW
	Desc     string  `json:"d"`            // English description
	Vector   string  `json:"c,omitempty"`  // CVSS vector string (e.g. AV:N/AC:L/...)
	CWE      string  `json:"w,omitempty"`  // Primary CWE (e.g. CWE-502)
	KEV      bool    `json:"k,omitempty"`  // true if in CISA Known Exploited Vulnerabilities
	Source   string  `json:"r,omitempty"`  // "NIST" or "CNA:<org>"
	Published string `json:"p,omitempty"` // YYYY-MM-DD
	Status   string  `json:"u,omitempty"` // vulnStatus (Analyzed, Modified, Awaiting Analysis…)
}

// ============================================================
// Main
// ============================================================

func main() {
	start := time.Now()
	log.Println("[+] NVD Intelligence Engine v2.0 — Booting...")

	apiKey := os.Getenv("NVD_API_KEY")
	if apiKey != "" {
		log.Println("[i] NVD_API_KEY detected — operating at elevated rate limit (50 req/30s).")
	} else {
		log.Println("[i] No NVD_API_KEY. Operating at unauthenticated rate (5 req/30s).")
	}

	// Make sure both possible output directories exist
	for _, dir := range []string{"data", filepath.Join("web", "data")} {
		os.MkdirAll(dir, 0755)
	}
	intelFile := filepath.Join("data", "nvd_intel.json")

	// Load existing dictionary so we accumulate across runs
	dictionary := make(map[string]CVEIntel)
	if raw, err := os.ReadFile(intelFile); err == nil {
		if err := json.Unmarshal(raw, &dictionary); err != nil {
			log.Printf("[-] Warning: existing intel file unparseable — rebuilding fresh.")
		} else {
			log.Printf("[i] Loaded %d existing signatures from %s.", len(dictionary), intelFile)
		}
	}

	// Fetch last 180 days by modification date — catches all recent activity
	// and accumulates over time into a growing dictionary
	now := time.Now().UTC()
	windows := []struct{ start, end time.Time }{
		{now.AddDate(0, 0, -90), now.AddDate(0, 0, -45)},
		{now.AddDate(0, 0, -45), now},
	}

	for i, w := range windows {
		log.Printf("[+] Fetching window %d/2: %s → %s",
			i+1,
			w.start.Format("2006-01-02"),
			w.end.Format("2006-01-02"),
		)
		if err := fetchWindow(w.start, w.end, dictionary, apiKey); err != nil {
			log.Printf("[-] Window %d failed: %v", i+1, err)
		}
	}

	// Serialize
	out, err := json.Marshal(dictionary)
	if err != nil {
		log.Fatalf("[-] FATAL: Failed to serialize dictionary: %v", err)
	}

	if err := os.WriteFile(intelFile, out, 0644); err != nil {
		log.Fatalf("[-] FATAL: Failed to write %s: %v", intelFile, err)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[+] Done in %s. Dictionary: %d threat signatures → %s (%.1f KB)",
		elapsed, len(dictionary), intelFile, float64(len(out))/1024.0)
}

// ============================================================
// Fetch a time window with full pagination
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
			startIdx,
			pageSize,
		)

		resp, err := nvdGet(url, apiKey)
		if err != nil {
			return fmt.Errorf("GET failed at startIndex=%d: %w", startIdx, err)
		}

		if total == -1 {
			total = resp.TotalResults
			log.Printf("  -> %d CVEs in this window. Paginating...", total)
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

		// Rate-limit sleep:
		// Unauthenticated: 5 req / 30s  → sleep 6.5s to be safe
		// Authenticated:   50 req / 30s → sleep 0.65s
		if apiKey != "" {
			time.Sleep(700 * time.Millisecond)
		} else {
			time.Sleep(6500 * time.Millisecond)
		}
	}
	log.Printf("  -> Processed %d signatures from this window.", added)
	return nil
}

// ============================================================
// HTTP helper
// ============================================================

func nvdGet(url, apiKey string) (*NVD2Response, error) {
	client := &http.Client{Timeout: 60 * time.Second}
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
		return nil, fmt.Errorf("HTTP 403: rate limit hit — increase sleep between requests")
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

// ============================================================
// Extract intel from a CVE2 entry
// ============================================================

func extractIntel(cve CVE2) CVEIntel {
	intel := CVEIntel{}

	// --- Description (English) ---
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			intel.Desc = d.Value
			break
		}
	}
	if intel.Desc == "" {
		intel.Desc = "No description available."
	}

	// --- CVSS Score — priority: NIST Primary > CNA Secondary > v2 fallback ---
	// Try v3.1 first
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
	// If NIST hasn't scored yet, use the CNA (Secondary) score
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
	// Last resort: CVSS v2
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

	// --- CWE — prefer NIST Primary classification ---
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
	// Fallback to any CWE
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

	// --- CISA KEV ---
	intel.KEV = cve.CisaExploitAdd != ""

	// --- Published date (YYYY-MM-DD) ---
	if len(cve.Published) >= 10 {
		intel.Published = cve.Published[:10]
	}

	// --- VulnStatus ---
	intel.Status = cve.VulnStatus

	return intel
}
