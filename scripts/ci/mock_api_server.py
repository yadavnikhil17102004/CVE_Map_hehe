#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path.cwd()
SAMPLE_DIR = ROOT / "sample-data"

with (SAMPLE_DIR / "sample_cves.json").open("r", encoding="utf-8") as f:
    SAMPLE_CVES = json.load(f)
with (SAMPLE_DIR / "sample_news.json").open("r", encoding="utf-8") as f:
    SAMPLE_NEWS = json.load(f)

# NOTE: Keep this mock aligned with real `/api/*` contracts; CI smoke fidelity depends on it.

INTEL_BY_CVE = {
    "CVE-2026-12345": {
        "s": 9.8,
        "v": "CRITICAL",
        "d": "Pre-auth remote code execution chain affecting internet-facing appliances.",
        "c": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "w": "CWE-78",
        "k": True,
        "r": "NIST",
        "p": "2026-06-12",
        "u": "Analyzed",
        "e": 0.91,
    },
    "CVE-2026-98765": {
        "s": 7.5,
        "v": "HIGH",
        "d": "Authenticated command execution requiring valid admin session.",
        "c": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "w": "CWE-287",
        "r": "NIST",
        "p": "2026-06-10",
        "u": "Analyzed",
        "e": 0.46,
    },
}


def sample_news_payload() -> dict:
    articles = list(SAMPLE_NEWS.get("articles", []))
    if articles:
        articles[0]["tier"] = 4
    if len(articles) > 1:
        articles[1]["tier"] = 2
    return {
        "last_updated": SAMPLE_NEWS.get("last_updated", "2026-06-19T09:00:00Z"),
        "articles": articles,
    }


def sample_news_paginated(page: int, per_page: int, tier: int | None, q: str | None) -> dict:
    payload = sample_news_payload()
    articles = payload["articles"]
    query = (q or "").strip().lower()
    filtered = []
    for item in articles:
        if tier is not None and item.get("tier") != tier:
            continue
        if query:
            haystack = " ".join(
                [
                    item.get("title", ""),
                    item.get("description", ""),
                    item.get("source", ""),
                ]
            ).lower()
            if query not in haystack:
                continue
        filtered.append(item)

    total = len(filtered)
    start = max(0, (page - 1) * per_page)
    end = start + per_page
    return {
        "last_updated": payload.get("last_updated"),
        "query": query,
        "tier": tier,
        "page": page,
        "per_page": per_page,
        "total": total,
        "has_more": end < total,
        "articles": filtered[start:end],
    }


def cves_for_year(year: int) -> list[dict]:
    if year == 2026:
        return SAMPLE_CVES.get("cves", [])
    return []


def response_json(handler: SimpleHTTPRequestHandler, payload: dict | list, code: int = 200) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def build_search_results(
    q: str,
    page: int,
    per_page: int,
    year_filter: int | None,
    severity: str | None,
    kev: bool | None,
) -> dict:
    query = q.strip().lower()
    matches: list[dict] = []
    for cve in cves_for_year(2026):
        cve_id = cve["cve_id"]
        intel = INTEL_BY_CVE.get(cve_id, {})
        if year_filter is not None and year_filter != 2026:
            continue
        if severity and intel.get("v") != severity:
            continue
        if kev is not None and bool(intel.get("k")) != kev:
            continue

        haystack = " ".join(
            [
                cve_id,
                intel.get("d", ""),
                intel.get("w", ""),
                *(r.get("full_name", "") for r in cve.get("repositories", [])),
                *(r.get("description", "") for r in cve.get("repositories", [])),
            ]
        ).lower()
        if query in haystack:
            matches.append(
                {
                    "year": 2026,
                    "cve_id": cve_id,
                    "repositories": cve.get("repositories", []),
                    "intel": intel,
                }
            )

    total = len(matches)
    offset = max(0, (page - 1) * per_page)
    return {
        "query": q,
        "page": page,
        "per_page": per_page,
        "total": total,
        "cves": matches[offset : offset + per_page],
    }


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/api/health":
            response_json(self, {"ok": True, "service": "ci-mock-api"})
            return

        m_cve = re.fullmatch(r"/api/cve/(\d{4})", path)
        if m_cve:
            year = int(m_cve.group(1))
            payload = {"year": year, "cves": cves_for_year(year)}
            response_json(self, payload)
            return

        m_intel_summary = re.fullmatch(r"/api/intel-summary/(\d{4})", path)
        if m_intel_summary:
            year = int(m_intel_summary.group(1))
            response_json(self, INTEL_BY_CVE if year == 2026 else {})
            return

        m_intel = re.fullmatch(r"/api/intel/(\d{4})", path)
        if m_intel:
            year = int(m_intel.group(1))
            page_raw = qs.get("page", [None])[0]
            per_page = int(qs.get("per_page", ["1000"])[0])
            cve_ids_raw = qs.get("cve_ids", [None])[0]
            data = INTEL_BY_CVE if year == 2026 else {}

            if cve_ids_raw:
                allowed = {token.strip().upper() for token in cve_ids_raw.split(",") if token.strip()}
                data = {k: v for k, v in data.items() if k in allowed}

            if page_raw is not None:
                page = max(1, int(page_raw))
                keys = sorted(data.keys())
                start = (page - 1) * per_page
                end = start + per_page
                sliced = {k: data[k] for k in keys[start:end]}
                response_json(
                    self,
                    {
                        "year": year,
                        "page": page,
                        "per_page": per_page,
                        "total": len(data),
                        "intel": sliced,
                    },
                )
                return

            response_json(self, data)
            return

        if path == "/api/news":
            page_raw = qs.get("page", [None])[0]
            q = qs.get("q", [None])[0]
            tier_raw = qs.get("tier", [None])[0]
            per_page = int(qs.get("per_page", ["50"])[0])
            limit_raw = qs.get("limit", [None])[0]

            tier = int(tier_raw) if tier_raw and tier_raw.isdigit() else None
            paginated = page_raw is not None or bool(q and q.strip()) or tier is not None
            if paginated:
                page = max(1, int(page_raw or "1"))
                per_page = max(1, min(200, per_page))
                response_json(self, sample_news_paginated(page, per_page, tier, q))
            else:
                payload = sample_news_payload()
                if limit_raw and limit_raw.isdigit():
                    payload["articles"] = payload["articles"][: int(limit_raw)]
                response_json(self, payload)
            return

        if path == "/api/search":
            q = qs.get("q", [""])[0]
            if q.strip() and len(q.strip()) < 2:
                response_json(self, {"detail": "q too short"}, code=HTTPStatus.BAD_REQUEST)
                return

            page = max(1, int(qs.get("page", ["1"])[0]))
            per_page = max(1, min(200, int(qs.get("per_page", ["50"])[0])))
            year_filter = int(qs.get("year", [0])[0]) if qs.get("year") else None
            severity = qs.get("severity", [None])[0]
            if severity:
                severity = severity.upper()
            kev_raw = qs.get("kev", [None])[0]
            kev = None if kev_raw is None else kev_raw.lower() == "true"
            response_json(self, build_search_results(q, page, per_page, year_filter, severity, kev))
            return

        m_stats = re.fullmatch(r"/api/intel-stats/(\d{4})", path)
        if m_stats:
            year = int(m_stats.group(1))
            if year == 2026:
                payload = {
                    "year": 2026,
                    "total": 2,
                    "critical_high": 2,
                    "kev_total": 1,
                    "avg_epss": 0.685,
                }
            else:
                payload = {
                    "year": year,
                    "total": 0,
                    "critical_high": 0,
                    "kev_total": 0,
                    "avg_epss": None,
                }
            response_json(
                self,
                payload,
            )
            return

        if path == "/api/ops/freshness":
            response_json(
                self,
                {
                    "status": "ok",
                    "updated_at": "2026-07-31T12:00:00Z",
                    "scrape": {"metric": "scrape", "epoch": 1785499200, "age_seconds": 1200, "threshold_seconds": 25200, "stale": False},
                    "news": {"metric": "news", "epoch": 1785502500, "age_seconds": 300, "threshold_seconds": 5400, "stale": False},
                    "backup": {"metric": "backup", "epoch": 1785477600, "age_seconds": 36000, "threshold_seconds": 93600, "stale": False},
                    "snapshot": {"metric": "snapshot", "epoch": 1785250000, "age_seconds": 262800, "threshold_seconds": 691200, "stale": False},
                },
            )
            return

        m_detail = re.fullmatch(r"/api/cve-detail/(CVE-\d{4}-\d{4,8})", path, re.IGNORECASE)
        if m_detail:
            cve_id = m_detail.group(1).upper()
            matches = [c for c in cves_for_year(2026) if c.get("cve_id") == cve_id]
            if not matches:
                response_json(self, {"detail": "cve not found"}, code=HTTPStatus.NOT_FOUND)
                return
            repos = matches[0].get("repositories", [])
            intel = INTEL_BY_CVE.get(cve_id, {})
            response_json(
                self,
                {
                    "year": 2026,
                    "cve_id": cve_id,
                    "intel": intel,
                    "repositories": repos,
                    "timeline": [
                        {"event": "Published", "time": intel.get("p"), "note": "NVD publication date"},
                        {"event": "Latest Repo Activity", "time": repos[0].get("pushed_at") if repos else None, "note": "Most recent repository push"},
                    ],
                    "related_news": [],
                },
            )
            return

        super().do_GET()


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("ci-mock-server listening on http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
