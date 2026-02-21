package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// NIST NVD bulk data feeds
const nvdJSONFeedURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
const nvdModifiedFeedURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"

// Structs to parse the NIST feed
type NVDFeed struct {
	CVEItems []CVEItem `json:"CVE_Items"`
}

type CVEItem struct {
	CVE    CVEDetails `json:"cve"`
	Impact Impact     `json:"impact"`
}

type CVEDetails struct {
	CVEDataMeta struct {
		ID string `json:"ID"`
	} `json:"CVE_data_meta"`
	Description struct {
		DescriptionData []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description_data"`
	} `json:"description"`
}

type Impact struct {
	BaseMetricV3 struct {
		CVSSV3 struct {
			BaseSeverity string  `json:"baseSeverity"`
			BaseScore    float64 `json:"baseScore"`
		} `json:"cvssV3"`
	} `json:"baseMetricV3"`
	BaseMetricV2 struct {
		Severity string `json:"severity"`
		CVSSV2   struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssV2"`
	} `json:"baseMetricV2"`
}

// Our ultra-compact intel dictionary format
type CVEIntel struct {
	Score    float64 `json:"s"` // e.g., 9.8
	Severity string  `json:"v"` // e.g., CRITICAL
	Desc     string  `json:"d"` // Description
}

func main() {
	start := time.Now()
	log.Println("[+] Booting Autonomous NVD Scraper Engine...")

	// 1. Ensure target directory exists
	dataDir := filepath.Join("web", "data")
	os.MkdirAll(dataDir, 0755)
	intelFile := filepath.Join(dataDir, "nvd_intel.json")

	// 2. Load existing dictionary if present (so we update, not overwrite historical)
	dictionary := make(map[string]CVEIntel)
	if data, err := os.ReadFile(intelFile); err == nil {
		if err := json.Unmarshal(data, &dictionary); err != nil {
			log.Printf("[-] Warning: Failed to parse existing %s format, building fresh.", intelFile)
		} else {
			log.Printf("[i] Loaded existing dictionary with %d signatures.", len(dictionary))
		}
	}

	// 3. Download the zipped bulk feed
	log.Println("[+] Engaging NIST Servers for Recent CVSS metrics...")
	if err := processFeed(nvdJSONFeedURL, dictionary); err != nil {
		log.Printf("[-] Failed to process recent feed: %v", err)
	}

	log.Println("[+] Engaging NIST Servers for Modified CVSS metrics...")
	if err := processFeed(nvdModifiedFeedURL, dictionary); err != nil {
		log.Printf("[-] Failed to process modified feed: %v", err)
	}

	// 4. Export zero-bloat JSON map
	finalData, err := json.Marshal(dictionary)
	if err != nil {
		log.Fatalf("[-] FATAL: Failed to compress dictionary: %v", err)
	}

	if err := os.WriteFile(intelFile, finalData, 0644); err != nil {
		log.Fatalf("[-] FATAL: Failed to write %s: %v", intelFile, err)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[+] Engine Cycle Complete in %s. Emitted %d threat signatures to %s (Size: %.2f KB)", 
		elapsed.String(), len(dictionary), intelFile, float64(len(finalData))/1024.0)
}

// Downloads the NIST zip file, extracts the JSON in memory, and parses the CVEs
func processFeed(feedURL string, dict map[string]CVEIntel) error {
	client := &http.Client{Timeout: 60 * time.Second}
	
	resp, err := client.Get(feedURL)
	if err != nil {
		return fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d received", resp.StatusCode)
	}

	// Read zip into memory
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create zip reader: %w", err)
	}

	// Pluck out the JSON file from inside the zip
	for _, zipFile := range zipReader.File {
		if strings.HasSuffix(zipFile.Name, ".json") {
			f, err := zipFile.Open()
			if err != nil {
				return err
			}
			
			var feed NVDFeed
			if err := json.NewDecoder(f).Decode(&feed); err != nil {
				f.Close()
				return fmt.Errorf("JSON decode error: %w", err)
			}
			f.Close()

			addedCount := 0
			// Process and compress each CVE
			for _, item := range feed.CVEItems {
				cveID := item.CVE.CVEDataMeta.ID
				
				// Validate format CVE-XXXX-XXXX
				if !regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`).MatchString(cveID) {
					continue
				}

				// Extract best description
				desc := "No description provided by NIST."
				for _, d := range item.CVE.Description.DescriptionData {
					if d.Lang == "en" {
						desc = d.Value
						break
					}
				}

				// Extract highest severity score
				score := 0.0
				severity := "UNK"
				
				if item.Impact.BaseMetricV3.CVSSV3.BaseSeverity != "" {
					score = item.Impact.BaseMetricV3.CVSSV3.BaseScore
					severity = item.Impact.BaseMetricV3.CVSSV3.BaseSeverity
				} else if item.Impact.BaseMetricV2.Severity != "" {
					score = item.Impact.BaseMetricV2.CVSSV2.BaseScore
					severity = item.Impact.BaseMetricV2.Severity
				}

				// Insert into dict
				dict[cveID] = CVEIntel{
					Score:    score,
					Severity: severity,
					Desc:     desc,
				}
				addedCount++
			}
			log.Printf("  -> Mapped %d active threats from internal feed.", addedCount)
			break
		}
	}
	return nil
}
