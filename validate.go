package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type YearData struct {
	Year int `json:"year"`
	CVEs []struct {
		CVEID string `json:"cve_id"`
	} `json:"cves"`
}

func main() {
	failures := make([]string, 0)

	addFail := func(msg string) {
		failures = append(failures, msg)
		fmt.Printf("✗ %s\n", msg)
	}
	ok := func(msg string) {
		fmt.Printf("✓ %s\n", msg)
	}
	warn := func(msg string) {
		fmt.Printf("! %s\n", msg)
	}

	// 1) CVE year data sanity
	yearFiles, err := filepath.Glob("data/[0-9][0-9][0-9][0-9].json")
	if err != nil {
		addFail(fmt.Sprintf("glob year files failed: %v", err))
	} else if len(yearFiles) == 0 {
		addFail("no data/YYYY.json files found")
	} else {
		sort.Strings(yearFiles)
		totalCVEs := 0
		yearsWithData := 0
		cveIDPattern := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
		otherBucketPattern := regexp.MustCompile(`^OTHER-\d{4}$`)
		invalidBucketCount := 0
		otherBucketCount := 0

		for _, f := range yearFiles {
			raw, err := os.ReadFile(f)
			if err != nil {
				addFail(fmt.Sprintf("read failed for %s: %v", f, err))
				continue
			}
			var yd YearData
			if err := json.Unmarshal(raw, &yd); err != nil {
				addFail(fmt.Sprintf("invalid JSON in %s: %v", f, err))
				continue
			}
			if len(yd.CVEs) > 0 {
				yearsWithData++
			}
			totalCVEs += len(yd.CVEs)

			for _, entry := range yd.CVEs {
				id := entry.CVEID
				switch {
				case cveIDPattern.MatchString(id):
					continue
				case otherBucketPattern.MatchString(id):
					otherBucketCount++
					continue
				default:
					invalidBucketCount++
					if invalidBucketCount <= 5 {
						warn(fmt.Sprintf("%s has non-strict cve_id bucket %q (expect CVE-YYYY-NNNN+ or OTHER-YYYY)", f, id))
					}
				}
			}
		}

		if otherBucketCount > 0 {
			warn(fmt.Sprintf("OTHER-* catch-all buckets present (%d across year files; not CVE ids)", otherBucketCount))
		}
		if invalidBucketCount > 5 {
			warn(fmt.Sprintf("%d additional non-strict cve_id buckets omitted from detailed warnings", invalidBucketCount-5))
		}

		if totalCVEs > 0 {
			ok(fmt.Sprintf("CVE records > 0 (%d total across %d year files, %d with data)", totalCVEs, len(yearFiles), yearsWithData))
		} else {
			addFail("CVE records count is 0 across all year files")
		}
	}

	// 2) Intel map sanity (year-scoped files; monolith no longer in repo)
	yearIntelFiles, err := filepath.Glob("data/nvd_intel_[0-9][0-9][0-9][0-9].json")
	if err != nil {
		addFail(fmt.Sprintf("glob year-scoped intel failed: %v", err))
	} else if len(yearIntelFiles) == 0 {
		addFail("no data/nvd_intel_YYYY.json files found")
	} else {
		sort.Strings(yearIntelFiles)
		intel := make(map[string]map[string]any)
		for _, f := range yearIntelFiles {
			raw, err := os.ReadFile(f)
			if err != nil {
				addFail(fmt.Sprintf("read failed for %s: %v", f, err))
				continue
			}
			var slice map[string]map[string]any
			if err := json.Unmarshal(raw, &slice); err != nil {
				addFail(fmt.Sprintf("invalid JSON in %s: %v", f, err))
				continue
			}
			for id, row := range slice {
				intel[id] = row
			}
		}

		if len(intel) == 0 {
			addFail("aggregated year intel has 0 records")
		} else {
			ok(fmt.Sprintf("year intel loaded (%d records from %d files)", len(intel), len(yearIntelFiles)))
		}

		kevCount := 0
		epssCount := 0
		requiredMissing := 0

		for cveID, row := range intel {
			_, hasS := row["s"]
			_, hasV := row["v"]
			_, hasD := row["d"]
			if !(hasS && hasV && hasD) {
				requiredMissing++
				if requiredMissing <= 3 {
					addFail(fmt.Sprintf("required keys missing for %s (need s,v,d)", cveID))
				}
			}

			if kev, ok := row["k"].(bool); ok && kev {
				kevCount++
			}
			if _, ok := row["e"].(float64); ok {
				epssCount++
			}
		}

		if requiredMissing == 0 {
			ok("required intel fields present (s,v,d)")
		} else {
			addFail(fmt.Sprintf("required intel fields missing in %d records", requiredMissing))
		}

		if kevCount > 0 {
			ok(fmt.Sprintf("KEV enrichment present (%d CVEs)", kevCount))
		} else {
			addFail("KEV enrichment count is 0")
		}

		epssCoverage := 0.0
		if len(intel) > 0 {
			epssCoverage = (float64(epssCount) / float64(len(intel))) * 100.0
		}
		if epssCount > 0 {
			ok(fmt.Sprintf("EPSS enrichment present (%d CVEs, %.2f%% coverage)", epssCount, epssCoverage))
		} else {
			addFail("EPSS enrichment count is 0 (likely FIRST endpoint/schema drift)")
		}

		const minEpssCoverage = 90.0
		if epssCoverage < minEpssCoverage {
			if strings.EqualFold(os.Getenv("ALLOW_LOW_EPSS_COVERAGE"), "true") {
				warn(fmt.Sprintf("EPSS coverage below %.2f%% (actual %.2f%%), bypassed by ALLOW_LOW_EPSS_COVERAGE=true", minEpssCoverage, epssCoverage))
			} else {
				addFail(fmt.Sprintf("EPSS coverage too low: %.2f%% (minimum %.2f%%)", epssCoverage, minEpssCoverage))
			}
		} else {
			ok(fmt.Sprintf("EPSS coverage threshold met (>= %.2f%%)", minEpssCoverage))
		}

		fmt.Printf("\nSummary:\n")
		fmt.Printf("CVEs processed: %d\n", len(intel))
		fmt.Printf("NVD matched: %d\n", len(intel))
		fmt.Printf("KEV matched: %d\n", kevCount)
		fmt.Printf("EPSS matched: %d\n", epssCount)
		fmt.Printf("EPSS coverage: %.2f%%\n", epssCoverage)
	}

	// 3) Year-scoped intel files parse check (redundant but fast sanity)
	yearIntelParseFiles, err := filepath.Glob("data/nvd_intel_[0-9][0-9][0-9][0-9].json")
	if err != nil {
		addFail(fmt.Sprintf("glob year-scoped intel parse failed: %v", err))
	} else if len(yearIntelParseFiles) == 0 {
		addFail("no data/nvd_intel_YYYY.json files found (parse pass)")
	} else {
		sort.Strings(yearIntelParseFiles)
		ok(fmt.Sprintf("year-scoped intel files found (%d files)", len(yearIntelParseFiles)))
		for _, f := range yearIntelParseFiles {
			raw, err := os.ReadFile(f)
			if err != nil {
				addFail(fmt.Sprintf("read failed for %s: %v", f, err))
				continue
			}
			var m map[string]map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				addFail(fmt.Sprintf("invalid JSON in %s: %v", f, err))
			}
		}
	}

	if len(failures) > 0 {
		fmt.Printf("\nValidation FAILED with %d issue(s).\n", len(failures))
		os.Exit(1)
	}

	fmt.Println("\nValidation PASSED")
}
