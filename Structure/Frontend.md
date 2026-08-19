# Frontend (Static Site)

> [!info] Purpose
> Provides an interactive, responsive dashboard and supporting pages built with plain HTML, CSS (Tailwind), and vanilla JavaScript.

## 📄 Pages
| File | Description |
|------|-------------|
| `index.html` | Main dashboard – shows CVE table, filters, charts, timeline, activity feed. |
| `docs.html` | Documentation / help – explains how to use the site, data sources, FAQs. |
| `news.html` | News feed interface – lists articles from `data/news.json` with search and source filtering. |
| `dashboard.html` | (Legacy or alternate dashboard) – may contain additional visualisations; check repo for usage. |

## 🎨 Styling
- **Tailwind CSS** via `tailwind.config.js` and `style.css` (output of Tailwind build).  
- Custom overrides in `style.css`.
- Responsive layout – works on mobile, tablet, desktop.

## 🧩 How the Dashboard Works (`index.html`)
1. **On load**, reads the current year from URL or defaults to present year.
2. **Fetches year‑scoped NVD intel**: `data/nvd_intel_<year>.json` (if missing, falls back to `data/nvd_intel.json`).
3. **Loads CVE‑repo mapping** for that year: `data/<year>.json`.
4. **Joins** the two datasets on CVE ID to produce rows for the table.
5. **Applies UI filters** (type, severity, KEV, EPSS) – implemented in JS; filtering is client‑side on the loaded dataset.
6. **Renders**:
   - Table with columns: CVE, Description, Repos (list with links), Severity, KEV badge, EPSS, Year.
   - Side panel: clicking a row shows detailed NVD info (CVSS, vector, CWE, references, etc.).
   - Timeline / trend chart: counts of CVEs per month (using Chart.js or similar – see script tags).
   - Live activity feed: recent additions (could be from git commit timestamps or a separate feed).
7. **Caching**: fetched JSON files are cached via browser `fetch`; service worker may be present (check `sw.js` if exists).

## 📰 News Page (`news.html`)
- Loads `data/news.json`.
- Shows articles in reverse chronological order.
- Provides search box (client‑side) and source filter dropdown (populated from unique sources in feed).
- Clicking an article opens the original source in a new tab.

## 📚 Docs Page (`docs.html`)
- Static markdown‑converted content (or hand‑written) explaining:
  - What CVE Map is
  - How to interpret scores
  - How to contribute
  - Links to external resources (NVD, CISA, EPSS)

## ⚙️ Assets
- `favicon.svg` – site icon.
- `assets/` – images, logos, dashboard preview.
- `scripts/` – optional helper scripts (e.g., performance benchmarks).
- `style.css` – compiled Tailwind CSS.
- `tailwind.config.js` – Tailwind configuration.

## 🛠️ Development
- No build step required for basic edits; just modify HTML/CSS/JS and reload.
- If changing Tailwind config, run:
  ```bash
  npx tailwindcss -i ./input.css -o ./style.css --watch
  ```
  (Assumes `input.css` contains Tailwind directives.)

## 📂 Related Files
- **HTML:** `index.html`, `docs.html`, `news.html`, `dashboard.html` (root)
- **CSS:** `style.css`, `input.css`, `tailwind.config.js`
- **JS:** Inline `<script>` tags in HTML files; any separate `.js` in root or `scripts/`.
- **Data consumed:** `data/nvd_intel_YYYY.json`, `data/YYYY.json`, `data/news.json`.

## 🏷️ Tags
`#frontend #html #css #tailwind #dashboard #static-site #javascript`
