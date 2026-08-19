# CVE Mapping (`cvemapping.go`)

> [!info] Purpose
> Correlates GitHub repositories containing exploit/PoC code with CVE identifiers.

## 🔍 What it does
1. **Accepts a GitHub personal access token** (`SYNC_TOKEN`) for authenticated API requests (to avoid rate limits).
2. **Queries GitHub Search API** for code matching patterns typical of exploit PoCs (e.g., `"CVE-2024-" filename:README.md`, `"exploit for"` etc.).  
   *(See source for exact regex patterns – the tool looks for CVE‑style strings in code, filenames, and repo descriptions.)*
3. **For each matching result**, extracts:
   - CVE ID (from matched text)
   - Repository metadata: clone URL, description, star count
4. **Deduplicates** by (CVE, repo) pair.
5. **Outputs a JSON file** per year: `data/YYYY.json` with structure:
   ```json
   {
     "cves": [
       {
         "cve_id": "CVE-2024-1234",
         "repos": [
           {"clone_url": "...", "description": "...", "stars": 42}
         ]
       }
     ]
   }
   ```
   *(Actual schema may include additional fields; see the generated files for exact shape.)*
6. **Can run incrementally** – if a year file already exists, it merges new findings.

## ⚙️ Workflow Diagram
```text
Start
  │
  ▼
[Read SYNC_TOKEN from env/flag]
  │
  ▼
[Loop over recent years (or all years via flag)]
  │
  ▼
[GitHub Search API → fetch code/repo matches for CVE patterns]
  │
  ▼
[Parse matches → extract CVE IDs + repo info]
  │
  ▼
[Dedupe (CVE, repo) pairs]
  │
  ▼
[Load existing data/YYYY.json (if any)]
  │
  ▼
[Merge new entries, sort, write back to data/YYYY.json]
  │
  ▼
End
```

## 📂 Related File
- **Source:** `cvemapping.go` (root of repository)
- **Output:** `data/YYYY.json` (one per year, e.g., `data/2024.json`)

## 🛠️ How to Run Locally
```bash
go build cvemapping.go
./cvemapping -github-token="$SYNC_TOKEN"
```
*(Optional flags: `-years=2020,2021,2022` to limit, `-output-dir=data` to change output location.)*

## 🏷️ Tags
`#cvemapping #go #github-api #cve #data-pipeline`
