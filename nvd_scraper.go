package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var cpeRegex = regexp.MustCompile(`^cpe:2\.3:[aoh]:([^:]+):([^:]+):`)

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
	ID                    string          `json:"id"`
	Published             string          `json:"published"`
	LastModified          string          `json:"lastModified"`
	VulnStatus            string          `json:"vulnStatus"`
	Descriptions          []LangValue     `json:"descriptions"`
	Metrics               Metrics2        `json:"metrics"`
	Weaknesses            []Weakness      `json:"weaknesses"`
	CisaExploitAdd        string          `json:"cisaExploitAdd,omitempty"`
	CisaVulnerabilityName string          `json:"cisaVulnerabilityName,omitempty"`
	Configurations        []Configuration `json:"configurations"`
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

type Configuration struct {
	Nodes []ConfigNode `json:"nodes"`
}

type ConfigNode struct {
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type CPEMatch struct {
	Criteria   string `json:"criteria"` // e.g. "cpe:2.3:a:apache:log4j:*:..."
	Vulnerable bool   `json:"vulnerable"`
}

// ============================================================
// Our compact output format — what lands in nvd_intel.json
// ============================================================

type CVEIntel struct {
	Score     float64  `json:"s"`           // CVSS base score
	Severity  string   `json:"v"`           // CRITICAL / HIGH / MEDIUM / LOW
	Desc      string   `json:"d"`           // English description
	Vector    string   `json:"c,omitempty"` // CVSS vector string
	CWE       string   `json:"w,omitempty"` // Primary CWE (e.g. CWE-502)
	KEV       bool     `json:"k,omitempty"` // true if in CISA Known Exploited Vulnerabilities
	Source    string   `json:"r,omitempty"` // "NIST" or "CNA"
	Published string   `json:"p,omitempty"` // YYYY-MM-DD
	Status    string   `json:"u,omitempty"` // vulnStatus
	EPSS      float64  `json:"e,omitempty"` // EPSS probability 0.0–1.0
	Products  []string `json:"q,omitempty"` // "vendor:product" pairs from CPE data
}

type EPSSResponse struct {
	Status     string      `json:"status"`
	StatusCode int         `json:"status-code"`
	Data       []EPSSEntry `json:"data"`
}

type EPSSEntry struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`       // returned as string e.g. "0.97345"
	Percentile string `json:"percentile"` // not used
}

func pgConnStringFromEnv() string {
	if url := strings.TrimSpace(os.Getenv("DATABASE_URL")); url != "" {
		return url
	}
	host := strings.TrimSpace(os.Getenv("POSTGRES_HOST"))
	db := strings.TrimSpace(os.Getenv("POSTGRES_DB"))
	user := strings.TrimSpace(os.Getenv("POSTGRES_USER"))
	password := os.Getenv("POSTGRES_PASSWORD")
	if host == "" || db == "" || user == "" || password == "" {
		return ""
	}
	port := strings.TrimSpace(os.Getenv("POSTGRES_PORT"))
	if port == "" {
		port = "5432"
	}
	sslmode := strings.TrimSpace(os.Getenv("POSTGRES_SSLMODE"))
	if sslmode == "" {
		sslmode = "disable"
	}
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, db, sslmode,
	)
}

func parseDateNullable(v string) *time.Time {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return nil
	}
	return &t
}

func envDuration(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Printf("[-] Invalid %s=%q, using default %s", name, raw, fallback)
		return fallback
	}
	return d
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		log.Printf("[-] Invalid %s=%q, using default %d", name, raw, fallback)
		return fallback
	}
	return v
}

func loadIntelFromPostgres(connString string) (map[string]CVEIntel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, err
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, `
SELECT cve_id, cvss_score, severity, description, cvss_vector, cwe, kev_flag, source,
       published_date, status, epss_score, products
FROM nvd_intel`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dictionary := make(map[string]CVEIntel)
	for rows.Next() {
		var (
			cveID     string
			score     float64
			severity  *string
			desc      *string
			vector    *string
			cwe       *string
			kev       *bool
			source    *string
			published *time.Time
			status    *string
			epss      *float64
			products  []string
		)
		if err := rows.Scan(
			&cveID, &score, &severity, &desc, &vector, &cwe, &kev, &source,
			&published, &status, &epss, &products,
		); err != nil {
			return nil, err
		}
		intel := CVEIntel{Score: score}
		if severity != nil {
			intel.Severity = *severity
		}
		if desc != nil {
			intel.Desc = *desc
		}
		if vector != nil {
			intel.Vector = *vector
		}
		if cwe != nil {
			intel.CWE = *cwe
		}
		if kev != nil {
			intel.KEV = *kev
		}
		if source != nil {
			intel.Source = *source
		}
		if published != nil {
			intel.Published = published.Format("2006-01-02")
		}
		if status != nil {
			intel.Status = *status
		}
		if epss != nil {
			intel.EPSS = *epss
		}
		if len(products) > 0 {
			intel.Products = products
		}
		dictionary[cveID] = intel
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return dictionary, nil
}

func upsertIntelToPostgres(dictionary map[string]CVEIntel) error {
	connString := pgConnStringFromEnv()
	if connString == "" {
		return nil
	}
	upsertTimeout := envDuration("NVD_UPSERT_TIMEOUT", 30*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), upsertTimeout)
	defer cancel()

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return err
	}
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	const sql = `
INSERT INTO nvd_intel (
  cve_id, year, cvss_score, severity, description, cvss_vector,
  cwe, kev_flag, source, published_date, status, epss_score, products, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,
  $7,$8,$9,$10,$11,$12,$13::jsonb,NOW()
)
ON CONFLICT (cve_id) DO UPDATE SET
  year = EXCLUDED.year,
  cvss_score = EXCLUDED.cvss_score,
  severity = EXCLUDED.severity,
  description = EXCLUDED.description,
  cvss_vector = EXCLUDED.cvss_vector,
  cwe = EXCLUDED.cwe,
  kev_flag = EXCLUDED.kev_flag,
  source = EXCLUDED.source,
  published_date = EXCLUDED.published_date,
  status = EXCLUDED.status,
  epss_score = EXCLUDED.epss_score,
  products = EXCLUDED.products,
  updated_at = NOW()
`

	yearRegex := regexp.MustCompile(`^CVE-(\d{4})-\d{4,}$`)
	batchSize := envInt("NVD_UPSERT_BATCH_SIZE", 2000)
	cveIDs := make([]string, 0, len(dictionary))
	for cveID := range dictionary {
		cveIDs = append(cveIDs, cveID)
	}
	sort.Strings(cveIDs)

	upserts := 0
	for start := 0; start < len(cveIDs); start += batchSize {
		end := start + batchSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}

		batchUpserts := 0
		for _, cveID := range cveIDs[start:end] {
			intel := dictionary[cveID]
			m := yearRegex.FindStringSubmatch(cveID)
			if m == nil {
				continue
			}
			year, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			productsJSON, _ := json.Marshal(intel.Products)
			if _, err := tx.Exec(
				ctx, sql,
				cveID, year, intel.Score, intel.Severity, intel.Desc, intel.Vector,
				intel.CWE, intel.KEV, intel.Source, parseDateNullable(intel.Published),
				intel.Status, intel.EPSS, string(productsJSON),
			); err != nil {
				_ = tx.Rollback(ctx)
				return err
			}
			batchUpserts++
		}

		if err := tx.Commit(ctx); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		upserts += batchUpserts
		log.Printf("[+] nvd_intel upsert batch complete: %d/%d rows", upserts, len(cveIDs))
	}

	log.Printf("[+] Postgres upsert complete for nvd_intel: %d rows (timeout=%s, batch_size=%d)", upserts, upsertTimeout, batchSize)
	return nil
}

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
		url := "https://api.first.org/data/v1/epss?cve=" + strings.Join(batch, ",")

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("  [-] EPSS fetch error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Printf("  [-] EPSS HTTP %d for batch starting at index %d", resp.StatusCode, i)
			time.Sleep(5 * time.Second)
			continue
		}

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
		time.Sleep(1 * time.Second) // be polite to FIRST.org
	}
	return result
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

	connString := pgConnStringFromEnv()
	if connString == "" {
		log.Fatal("[-] Postgres connection is required (DATABASE_URL or POSTGRES_* env vars).")
	}
	dictionary, err := loadIntelFromPostgres(connString)
	if err != nil {
		log.Fatalf("[-] Failed loading baseline intel from Postgres: %v", err)
	}
	log.Printf("[i] Loaded %d existing signatures from Postgres.", len(dictionary))

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
	// Source CVE IDs from Postgres.
	log.Println("[+] Phase 2: Targeted backfill for unscored CVEs...")
	missing := collectMissingCVEsFromPostgres(dictionary)
	log.Printf("  Found %d CVEs to backfill (missing or unscored).", len(missing))
	if len(missing) > 0 {
		fetchTargeted(missing, dictionary, apiKey)
	}

	// ── Phase 3: EPSS enrichment ─────────────────────────────
	log.Println("[+] Phase 3: Fetching EPSS scores from FIRST.org...")
	allIDs := make([]string, 0, len(dictionary))
	for id := range dictionary {
		allIDs = append(allIDs, id)
	}
	sort.Strings(allIDs)
	epssScores := fetchEPSS(allIDs)
	if len(dictionary) > 0 && len(epssScores) == 0 {
		if strings.EqualFold(os.Getenv("ALLOW_EMPTY_EPSS"), "true") {
			log.Printf("[!] EPSS enrichment returned 0 records; continuing due to ALLOW_EMPTY_EPSS=true")
		} else {
			log.Fatal("[-] EPSS enrichment returned 0 records; refusing to publish silently broken intel. Set ALLOW_EMPTY_EPSS=true only for emergency bypass.")
		}
	}
	enriched := 0
	kevMatched := 0
	for id, intel := range dictionary {
		if intel.KEV {
			kevMatched++
		}
		if score, ok := epssScores[id]; ok {
			intel.EPSS = score
			dictionary[id] = intel
			enriched++
		}
	}
	epssCoverage := 0.0
	if len(dictionary) > 0 {
		epssCoverage = (float64(enriched) / float64(len(dictionary))) * 100.0
	}
	log.Printf("  -> EPSS records loaded: %d", len(epssScores))
	log.Printf("  -> EPSS scores applied to %d/%d CVEs (%.2f%% coverage).", enriched, len(dictionary), epssCoverage)
	log.Printf("  -> KEV matched: %d/%d CVEs.", kevMatched, len(dictionary))

	// ── Persist output ───────────────────────────────────────
	if err := upsertIntelToPostgres(dictionary); err != nil {
		log.Fatalf("[-] Postgres upsert failed: %v", err)
	}
	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[+] Enrichment summary: CVEs processed=%d, NVD matched=%d, KEV matched=%d, EPSS matched=%d, EPSS coverage=%.2f%%",
		len(allIDs), len(dictionary), kevMatched, enriched, epssCoverage)
	log.Printf("[+] Done in %s. Dictionary: %d signatures.", elapsed, len(dictionary))
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
// Phase 2: Collect missing/unscored CVE IDs from Postgres
// ============================================================

// collectMissingCVEsFromPostgres reads distinct CVE IDs from cve_repos and
// identifies targets that are missing/unscored in nvd_intel dictionary.
// It keeps the same "stale Deferred" retry rule as previous file-based logic.
func collectMissingCVEsFromPostgres(dict map[string]CVEIntel) []string {
	connString := pgConnStringFromEnv()
	if connString == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		log.Printf("[-] Postgres connect failed for targeted backfill source: %v", err)
		return nil
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, `SELECT DISTINCT cve_id FROM cve_repos ORDER BY cve_id`)
	if err != nil {
		log.Printf("[-] Postgres query failed for targeted backfill source: %v", err)
		return nil
	}
	defer rows.Close()

	validCVE := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cutoff := time.Now().AddDate(0, 0, -30)
	var missing []string
	seen := make(map[string]bool)

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		if !validCVE.MatchString(id) || seen[id] {
			continue
		}
		seen[id] = true

		existing, ok := dict[id]
		if (!ok || existing.Score == 0) && existing.Status != "Deferred" {
			missing = append(missing, id)
			continue
		}
		if existing.Status == "Deferred" && existing.Published != "" {
			pub, err := time.Parse("2006-01-02", existing.Published)
			if err == nil && pub.Before(cutoff) {
				missing = append(missing, id)
			}
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("[-] Postgres rows iteration error: %v", err)
	}
	log.Printf("[i] Targeted backfill source: Postgres cve_repos (%d candidate CVEs)", len(seen))
	return missing
}

// ============================================================
// Phase 2: Fetch individual CVEs by ID
// ============================================================

func fetchTargeted(cveIDs []string, dict map[string]CVEIntel, apiKey string) {
	const phaseBudget = 8 * time.Minute // keeps total run under ~10 min
	deadline := time.Now().Add(phaseBudget)

	fetched := 0
	failed := 0

	for i, id := range cveIDs {
		// Time-based stop — any remainder picked up on the next 6h cycle
		if time.Now().After(deadline) {
			remaining := len(cveIDs) - i
			log.Printf("  [i] 8-min budget reached. %d CVEs remaining — will continue in next run.", remaining)
			break
		}

		url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", id)
		resp, err := nvdGet(url, apiKey)
		if err != nil {
			log.Printf("  [-] Failed to fetch %s: %v", id, err)
			failed++
			rateSleep(apiKey)
			continue
		}
		if len(resp.Vulnerabilities) > 0 {
			dict[id] = extractIntel(resp.Vulnerabilities[0].CVE)
			fetched++
		}
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

// nvdClient is a shared HTTP client so that TCP/TLS connections are reused
// across the many sequential NVD requests, reducing latency and overhead.
var nvdClient = &http.Client{
	Timeout: envDuration("NVD_HTTP_TIMEOUT", 2*time.Minute),
}

func nvdGet(url, apiKey string) (*NVD2Response, error) {
	maxRetries := envInt("NVD_HTTP_MAX_RETRIES", 3)
	for attempt := 1; attempt <= maxRetries+1; attempt++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err := nvdClient.Do(req)
		if err != nil {
			if attempt <= maxRetries {
				backoff := time.Duration(2*attempt) * time.Second
				log.Printf("  [i] NVD request attempt %d/%d failed: %v (retry in %s)", attempt, maxRetries+1, err, backoff)
				time.Sleep(backoff)
				continue
			}
			return nil, err
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			resp.Body.Close()
			if attempt <= maxRetries {
				time.Sleep(35 * time.Second)
				continue
			}
			return nil, fmt.Errorf("HTTP %d after retries", resp.StatusCode)
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt <= maxRetries {
				backoff := time.Duration(2*attempt) * time.Second
				time.Sleep(backoff)
				continue
			}
			return nil, fmt.Errorf("HTTP %d after retries", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if attempt <= maxRetries {
				backoff := time.Duration(2*attempt) * time.Second
				log.Printf("  [i] NVD read attempt %d/%d failed: %v (retry in %s)", attempt, maxRetries+1, err, backoff)
				time.Sleep(backoff)
				continue
			}
			return nil, err
		}

		var result NVD2Response
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("JSON parse error: %w", err)
		}
		return &result, nil
	}

	return nil, fmt.Errorf("unreachable NVD retry loop")
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
// CPE product extraction
// ============================================================

// extractProducts parses CPE criteria strings and returns unique "vendor:product" pairs.
func extractProducts(configs []Configuration) []string {
	seen := make(map[string]bool)
	var products []string
	// CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
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
	// Combine v3.1 and v3.0 metrics once to avoid two separate slice allocations.
	scoreSet := false
	allV3 := append(cve.Metrics.CVSSMetricV31, cve.Metrics.CVSSMetricV30...)
	for _, m := range allV3 {
		if m.Type == "Primary" && m.CVSSData.BaseScore > 0 {
			intel.Score = m.CVSSData.BaseScore
			intel.Severity = m.CVSSData.BaseSeverity
			intel.Vector = m.CVSSData.VectorString
			intel.Source = "NIST"
			scoreSet = true
			break
		}
	}
	if !scoreSet {
		for _, m := range allV3 {
			if m.Type == "Secondary" && m.CVSSData.BaseScore > 0 {
				intel.Score = m.CVSSData.BaseScore
				intel.Severity = m.CVSSData.BaseSeverity
				intel.Vector = m.CVSSData.VectorString
				intel.Source = "CNA"
				scoreSet = true
				break
			}
		}
	}
	if !scoreSet {
		for _, m := range cve.Metrics.CVSSMetricV2 {
			if m.CVSSData.BaseScore > 0 {
				intel.Score = m.CVSSData.BaseScore
				intel.Severity = m.BaseSeverity
				intel.Vector = m.CVSSData.VectorString
				intel.Source = "CVSSv2"
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

	// CPE product mapping
	intel.Products = extractProducts(cve.Configurations)

	return intel
}
