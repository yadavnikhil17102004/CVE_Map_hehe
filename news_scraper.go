package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Define unified output struct for frontend
type NewsItem struct {
	Title       string `json:"title"`
	Link        string `json:"link"`
	Description string `json:"description"`
	PubDate     string `json:"pub_date"`
	Source      string `json:"source"`
	Tier        int    `json:"tier"`
	ImageURL    string `json:"image_url"`
}

type NewsData struct {
	LastUpdated string     `json:"last_updated"`
	Articles    []NewsItem `json:"articles"`
}

// RSS XML Structs
type RSS struct {
	XMLName xml.Name `xml:"rss"`
	Channel Channel  `xml:"channel"`
}

type Channel struct {
	Title    string `xml:"title"`
	ItemList []Item `xml:"item"`
}

type Item struct {
	Title       string        `xml:"title"`
	Link        string        `xml:"link"`
	Description string        `xml:"description"`
	Content     string        `xml:"encoded"`
	PubDate     string        `xml:"pubDate"`
	Enclosure   *Enclosure    `xml:"enclosure"`
	Media       *MediaContent `xml:"content"`
}

type Enclosure struct {
	URL  string `xml:"url,attr"`
	Type string `xml:"type,attr"`
}

type MediaContent struct {
	URL    string `xml:"url,attr"`
	Medium string `xml:"medium,attr"`
}

const (
	timeout        = 15 * time.Second
	maxItemsPerSrc = 15 // Limit how many items we keep per source so the feed isn't huge
)

// rssClient is a shared HTTP client so TCP/TLS connections are reused across
// concurrent feed fetches, reducing per-goroutine overhead.
var rssClient = &http.Client{Timeout: timeout}

type FeedSource struct {
	URL  string
	Tier int
}

var feeds = map[string]FeedSource{
	// Tier 1: Raw vulnerability feeds
	"CISA Advisories":     {"https://www.cisa.gov/cybersecurity-advisories/all.xml", 1},
	"Rapid7":              {"https://blog.rapid7.com/rss/", 1},
	// Tier 2: PoC / exploit code databases
	"Packet Storm":        {"https://rss.packetstormsecurity.com/files/", 2},
	// Tier 3: Research & writeups
	"The Hacker News":     {"https://feeds.feedburner.com/TheHackersNews", 3},
	"BleepingComputer":    {"https://www.bleepingcomputer.com/feed/", 3},
	"Cyber Security News": {"https://cybersecuritynews.com/feed/", 3},
	// Tier 4: Bleeding-edge
	"GitHub Security":     {"https://github.blog/security/feed/", 4},
	"Zero Day Initiative":  {"https://www.zerodayinitiative.com/rss/published/", 4},
	// Tier 5: The REAL Hacker Feed
	"r/netsec":            {"https://www.reddit.com/r/netsec/.rss", 5},
	"r/ExploitDev":        {"https://www.reddit.com/r/ExploitDev/.rss", 5},
	"r/bugbounty":         {"https://www.reddit.com/r/bugbounty/.rss", 5},
}

var imgRegex = regexp.MustCompile(`(?i)<img[^>]+src="([^">]+)"`)

func main() {
	start := time.Now()
	log.Println("[+] Live Cyber News Scraper Booting...")

	// Make sure data directory exists
	os.MkdirAll("data", 0755)

	var allItems []NewsItem
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fetch all feeds concurrently
	for sourceName, sourceInfo := range feeds {
		wg.Add(1)
		go func(name string, info FeedSource) {
			defer wg.Done()
			items, err := fetchAndParseRSS(name, info)
			if err != nil {
				log.Printf("[-] Failed to fetch %s: %v", name, err)
				return
			}
			mu.Lock()
			allItems = append(allItems, items...)
			mu.Unlock()
		}(sourceName, sourceInfo)
	}

	wg.Wait()

	// Sort articles by date descending (newest first)
	sort.SliceStable(allItems, func(i, j int) bool {
		t1 := parseTime(allItems[i].PubDate)
		t2 := parseTime(allItems[j].PubDate)
		return t1.After(t2)
	})

	// Compile into final JSON struct
	data := NewsData{
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Articles:    allItems,
	}

	// Write to JSON file
	outFile := filepath.Join("data", "news.json")
	outJSON, err := json.MarshalIndent(data, "", "  ") // Indent for readability
	if err != nil {
		log.Fatalf("[-] FATAL: Failed to serialize news items: %v", err)
	}

	if err := os.WriteFile(outFile, outJSON, 0644); err != nil {
		log.Fatalf("[-] FATAL: Failed to write %s: %v", outFile, err)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[+] Done in %s. Scraped %d articles -> %s", elapsed, len(allItems), outFile)
}

// Worker to fetch and parse an RSS feed
func fetchAndParseRSS(sourceName string, source FeedSource) ([]NewsItem, error) {
	log.Printf("  -> Fetching %s...", sourceName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", source.URL, nil)
	if err != nil {
		return nil, err
	}
	// Use a transparent scraper User-Agent instead of impersonating a specific
	// browser or OS, which avoids misrepresenting the request origin.
	req.Header.Set("User-Agent", "CVEMap-NewsScraper/1.0 (+https://github.com/yadavnikhil17102004/CVE_Map_hehe)")

	resp, err := rssClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Stream-parse the XML directly from the response body instead of
	// reading the entire payload into memory first.
	var rss RSS
	if err := xml.NewDecoder(resp.Body).Decode(&rss); err != nil {
		return nil, fmt.Errorf("XML parse error: %v", err)
	}

	var items []NewsItem
	for i, item := range rss.Channel.ItemList {
		if i >= maxItemsPerSrc {
			break
		}

		// Try to extract an image URL
		imageURL := ""
		if item.Media != nil && item.Media.URL != "" {
			imageURL = item.Media.URL
		} else if item.Enclosure != nil && item.Enclosure.URL != "" && strings.HasPrefix(item.Enclosure.Type, "image/") {
			imageURL = item.Enclosure.URL
		} else {
			// Regex parse description or content for an image
			matches := imgRegex.FindStringSubmatch(item.Content)
			if len(matches) > 1 {
				imageURL = matches[1]
			} else {
				matches = imgRegex.FindStringSubmatch(item.Description)
				if len(matches) > 1 {
					imageURL = matches[1]
				}
			}
		}

		// Clean up the description
		cleanDesc := cleanHTML(item.Description)
		if len(cleanDesc) > 200 {
			cleanDesc = cleanDesc[:197] + "..." // Truncate cleanly for UI
		}

		items = append(items, NewsItem{
			Title:       item.Title,
			Link:        item.Link,
			Description: strings.TrimSpace(cleanDesc),
			PubDate:     item.PubDate,
			Source:      sourceName,
			Tier:        source.Tier,
			ImageURL:    imageURL,
		})
	}

	return items, nil
}

// Helper: Attempt to parse RSS date strings to standard time.Time for sorting
func parseTime(dateStr string) time.Time {
	// Standard RSS format is time.RFC1123Z or time.RFC1123
	layouts := []string{
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822,
		time.RFC822Z,
		time.RFC3339,
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, dateStr); err == nil {
			return t
		}
	}
	return time.Time{} // Return zero-time if unknown format, pushes to bottom
}

// Helper: Strip basic HTML tags from descriptions
func cleanHTML(s string) string {
	var builder strings.Builder
	inTag := false
	for _, runeValue := range s {
		if runeValue == '<' {
			inTag = true
			continue
		}
		if runeValue == '>' {
			inTag = false
			continue
		}
		if !inTag {
			builder.WriteRune(runeValue)
		}
	}

	// Clean up newlines
	clean := strings.ReplaceAll(builder.String(), "\n", " ")
	clean = strings.ReplaceAll(clean, "\r", "")
	return clean
}
