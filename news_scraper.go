package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
}

const (
	timeout        = 15 * time.Second
	maxItemsPerSrc = 15 // Limit how many items we keep per source so the feed isn't huge
)

var feeds = map[string]string{
	"BleepingComputer": "https://www.bleepingcomputer.com/feed/",
	"The Hacker News":  "https://feeds.feedburner.com/TheHackersNews",
}

func main() {
	start := time.Now()
	log.Println("[+] Live Cyber News Scraper Booting...")

	// Make sure data directory exists
	os.MkdirAll("data", 0755)

	var allItems []NewsItem
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fetch all feeds concurrently
	for sourceName, rssURL := range feeds {
		wg.Add(1)
		go func(name, url string) {
			defer wg.Done()
			items, err := fetchAndParseRSS(name, url)
			if err != nil {
				log.Printf("[-] Failed to fetch %s: %v", name, err)
				return
			}
			mu.Lock()
			allItems = append(allItems, items...)
			mu.Unlock()
		}(sourceName, rssURL)
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
	outJSON, err := json.Marshal(data)
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
func fetchAndParseRSS(sourceName, url string) ([]NewsItem, error) {
	log.Printf("  -> Fetching %s...", sourceName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Act like a browser to prevent 403s
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rss RSS
	if err := xml.Unmarshal(body, &rss); err != nil {
		return nil, fmt.Errorf("XML parse error: %v", err)
	}

	var items []NewsItem
	for i, item := range rss.Channel.ItemList {
		if i >= maxItemsPerSrc {
			break
		}
		
		// Clean up the description (often contains HTML from RSS feeds)
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
