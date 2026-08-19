# News Scraper (`news_scraper.go`)

> [!info] Purpose
> Curates an hourly feed of cybersecurity news from RSS/Atom sources.

## 🔍 What it does
1. **Defines a list of trusted security news feeds** (RSS/ATP) – e.g., The Hacker News, Krebs on Security, SecurityWeek, etc. (list defined in source).
2. **For each feed**, performs an HTTP GET request, parsing the XML (using Go's `encoding/xml` or a library) to extract:
   - Article title
   - URL
   - Publication date
   - Summary / description
   - Source name
3. **Filters entries**:
   - Deduplicates by URL or title+source.
   - Optionally removes items older than a cutoff (e.g., last 48 h).
   - May apply keyword‑based scoring or tagging (implementation defined).
4. **Sorts** entries by publication date (newest first).
5. **Outputs** a single JSON file: `data/news.json` with structure:
   ```json
   {
     "generated_at": "2026-08-19T20:15:00Z",
     "articles": [
       {
         "title": "Example Article",
         "url": "https://example.com/article",
         "source": "The Hacker News",
         "published_at": "2026-08-19T18:00:00Z",
         "summary": "Short description…"
       }
     ]
   }
   ```
6. **Designed to be run frequently** (hourly via GitHub Actions) to keep the news feed fresh.

## ⚙️ Workflow Diagram
```text
Start
  │
  ▼
[Load feed URLs list (from source code or config)]
  │
  ▼
[For each feed URL:
   │
   ├─ HTTP GET (with timeout, retry)
   │
   ├─ Parse XML → extract <item> or <entry> nodes
   │
   └─ For each item:
        ├─ Pull title, link, pubDate, description
        ├─ Normalize date to RFC3339/ISO8601
        └─ Build article object
]
  │
  ▼
[Dedupe articles (by URL or title+source)]
  │
  ▼
[Filter by age (if configured)]
  │
  ▼
[Sort by published_at DESC]
  │
  ▼
[Wrap in envelope with generated_at timestamp]
  │
  ▼
[Write JSON to data/news.json (atomic write → temp then rename)]
  │
  ▼
End
```

## 📂 Related File
- **Source:** `news_scraper.go` (root of repository)
- **Output:** `data/news.json` (single file, overwritten each run)

## 🛠️ How to Run Locally
```bash
go build news_scraper.go
./news_scraper
```
*(No required flags; optionally set `-output=data/news.json` or `-timeout=10s` if supported.)*

## 🏷️ Tags
`#news-scraper #go #rss #cybersecurity-news #data-pipeline`
