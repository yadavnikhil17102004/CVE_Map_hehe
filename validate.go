package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func envDurationSeconds(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return fallback
	}
	return time.Duration(secs) * time.Second
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

func countInt64(ctx context.Context, pool *pgxpool.Pool, query string, args ...any) (int64, error) {
	var v int64
	if err := pool.QueryRow(ctx, query, args...).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

func main() {
	failures := make([]string, 0)

	addFail := func(msg string) {
		failures = append(failures, msg)
		fmt.Printf("[FAIL] %s\n", msg)
	}
	ok := func(msg string) {
		fmt.Printf("[OK] %s\n", msg)
	}
	warn := func(msg string) {
		fmt.Printf("[WARN] %s\n", msg)
	}

	connString := pgConnStringFromEnv()
	if connString == "" {
		addFail("database connection not configured via DATABASE_URL or POSTGRES_* env vars")
		fmt.Printf("\nValidation FAILED with %d issue(s).\n", len(failures))
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), envDurationSeconds("VALIDATE_TIMEOUT_SECONDS", 180*time.Second))
	defer cancel()
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		addFail(fmt.Sprintf("database connect failed: %v", err))
		fmt.Printf("\nValidation FAILED with %d issue(s).\n", len(failures))
		os.Exit(1)
	}
	defer pool.Close()

	// 1) cve_repos sanity
	cveRepoRows, err := countInt64(ctx, pool, `SELECT COUNT(*) FROM cve_repos`)
	if err != nil {
		addFail(fmt.Sprintf("count cve_repos failed: %v", err))
	} else if cveRepoRows == 0 {
		addFail("cve_repos has 0 rows")
	} else {
		ok(fmt.Sprintf("cve_repos rows > 0 (%d)", cveRepoRows))
	}

	distinctRepoCVEs, err := countInt64(ctx, pool, `SELECT COUNT(DISTINCT cve_id) FROM cve_repos`)
	if err != nil {
		addFail(fmt.Sprintf("count distinct cve_repos.cve_id failed: %v", err))
	} else {
		ok(fmt.Sprintf("distinct CVEs in cve_repos: %d", distinctRepoCVEs))
	}

	// 2) nvd_intel sanity and required fields
	intelRows, err := countInt64(ctx, pool, `SELECT COUNT(*) FROM nvd_intel`)
	if err != nil {
		addFail(fmt.Sprintf("count nvd_intel failed: %v", err))
	} else if intelRows == 0 {
		addFail("nvd_intel has 0 rows")
	} else {
		ok(fmt.Sprintf("nvd_intel rows > 0 (%d)", intelRows))
	}

	missingRequired, err := countInt64(
		ctx,
		pool,
		`SELECT COUNT(*) FROM nvd_intel
         WHERE cvss_score IS NULL
            OR description IS NULL OR description = ''
            OR (
                 COALESCE(status, '') NOT IN ('Rejected', 'Deferred', 'Awaiting Analysis', 'Received', 'Undergoing Analysis')
                 AND (severity IS NULL OR severity = '')
               )`,
	)
	if err != nil {
		addFail(fmt.Sprintf("required-field query failed: %v", err))
	} else if missingRequired > 0 {
		pct := 0.0
		if intelRows > 0 {
			pct = (float64(missingRequired) / float64(intelRows)) * 100.0
		}
		if pct > 0.05 {
			addFail(fmt.Sprintf("required intel fields missing in %d records (%.4f%%)", missingRequired, pct))
		} else {
			warn(fmt.Sprintf("required intel field gaps in %d records (%.4f%%) — below failure threshold", missingRequired, pct))
		}
	} else {
		ok("required intel fields present (cvss_score, description, and severity where applicable)")
	}

	severityDeferredCount, err := countInt64(
		ctx,
		pool,
		`SELECT COUNT(*) FROM nvd_intel
         WHERE (severity IS NULL OR severity = '')
           AND COALESCE(status, '') IN ('Rejected', 'Deferred', 'Awaiting Analysis', 'Received', 'Undergoing Analysis')`,
	)
	if err == nil && severityDeferredCount > 0 {
		warn(fmt.Sprintf("severity intentionally absent on %d records in non-scored/rejected statuses", severityDeferredCount))
	}

	kevCount, err := countInt64(ctx, pool, `SELECT COUNT(*) FROM nvd_intel WHERE kev_flag = true`)
	if err != nil {
		addFail(fmt.Sprintf("KEV count query failed: %v", err))
	} else if kevCount == 0 {
		addFail("KEV enrichment count is 0")
	} else {
		ok(fmt.Sprintf("KEV enrichment present (%d CVEs)", kevCount))
	}

	epssCount, err := countInt64(ctx, pool, `SELECT COUNT(*) FROM nvd_intel WHERE epss_score IS NOT NULL`)
	if err != nil {
		addFail(fmt.Sprintf("EPSS count query failed: %v", err))
	} else if epssCount == 0 {
		addFail("EPSS enrichment count is 0")
	} else {
		epssCoverage := 0.0
		if intelRows > 0 {
			epssCoverage = (float64(epssCount) / float64(intelRows)) * 100.0
		}
		ok(fmt.Sprintf("EPSS enrichment present (%d CVEs, %.2f%% coverage)", epssCount, epssCoverage))

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
	}

	// 3) Year-scoped sanity in DB
	yearsInRepos, err := countInt64(ctx, pool, `SELECT COUNT(DISTINCT year) FROM cve_repos`)
	if err != nil {
		addFail(fmt.Sprintf("year coverage query for cve_repos failed: %v", err))
	} else if yearsInRepos == 0 {
		addFail("cve_repos has 0 distinct years")
	} else {
		ok(fmt.Sprintf("year coverage in cve_repos: %d distinct years", yearsInRepos))
	}

	yearsInIntel, err := countInt64(ctx, pool, `SELECT COUNT(DISTINCT year) FROM nvd_intel`)
	if err != nil {
		addFail(fmt.Sprintf("year coverage query for nvd_intel failed: %v", err))
	} else if yearsInIntel == 0 {
		addFail("nvd_intel has 0 distinct years")
	} else {
		ok(fmt.Sprintf("year coverage in nvd_intel: %d distinct years", yearsInIntel))
	}

	// 4) News sanity (DB-backed equivalent of former news.json presence)
	newsRows, err := countInt64(ctx, pool, `SELECT COUNT(*) FROM news_items`)
	if err != nil {
		addFail(fmt.Sprintf("count news_items failed: %v", err))
	} else if newsRows == 0 {
		warn("news_items has 0 rows")
	} else {
		ok(fmt.Sprintf("news_items rows > 0 (%d)", newsRows))
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("cve_repos rows: %d\n", cveRepoRows)
	fmt.Printf("cve_repos distinct CVEs: %d\n", distinctRepoCVEs)
	fmt.Printf("nvd_intel rows: %d\n", intelRows)
	fmt.Printf("nvd_intel KEV rows: %d\n", kevCount)
	fmt.Printf("nvd_intel EPSS rows: %d\n", epssCount)
	fmt.Printf("news_items rows: %d\n", newsRows)

	if len(failures) > 0 {
		fmt.Printf("\nValidation FAILED with %d issue(s).\n", len(failures))
		os.Exit(1)
	}

	fmt.Println("\nValidation PASSED")
}
