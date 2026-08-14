#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Any

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

BASE_URL = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
ROOT = Path.cwd()
OUT_DIR = ROOT / "artifacts" / "issue-6"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "ci-smoke-results.json"
FAILSHOT = OUT_DIR / "failure.png"


@dataclass
class Check:
    name: str
    data: dict[str, Any]


summary: dict[str, Any] = {
    "baseURL": BASE_URL,
    "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "checks": [],
}


def parse_count(text: str | None) -> int | None:
    if not text:
        return None
    m = re.search(r"(\d[\d,]*)", text)
    return int(m.group(1).replace(",", "")) if m else None


def wait_for(predicate: Callable[[], bool], label: str, timeout_s: float = 15.0, interval_s: float = 0.25) -> None:
    started = time.time()
    last_err: Exception | None = None
    while time.time() - started < timeout_s:
        try:
            if predicate():
                return
        except Exception as exc:  # pragma: no cover - diagnostic path
            last_err = exc
        time.sleep(interval_s)
    detail = f" ({last_err})" if last_err else ""
    raise TimeoutError(f"Timed out waiting for {label}{detail}")


def record(name: str, **data: Any) -> None:
    summary["checks"].append(asdict(Check(name=name, data=data)))


def text_of(locator) -> str:
    return (locator.text_content() or "").strip()


def cve_from_row_text(text: str) -> str:
    m = re.search(r"CVE-\d{4}-\d{4,7}", text)
    if not m:
        raise RuntimeError(f"Could not parse CVE id from row text: {text!r}")
    return m.group(0)


def smoke_dashboard(page) -> None:
    page.goto(f"{BASE_URL}/dashboard.html", wait_until="domcontentloaded")
    wait_for(lambda: page.locator("#cve-list .cve-row").count() > 0, "dashboard rows")

    initial_text = text_of(page.locator("#result-count"))
    initial_count = parse_count(initial_text)
    if not initial_count or initial_count < 1:
        raise RuntimeError(f"Dashboard did not expose a usable result count: {initial_text or '(blank)'}")

    first_row_text = text_of(page.locator("#cve-list .cve-row").first)
    first_cve = cve_from_row_text(first_row_text)
    print(f"[dashboard] initial_count={initial_count}, probe_cve={first_cve}")

    search_input = page.locator("#search-input")
    search_input.fill(first_cve)
    wait_for(
        lambda: (parse_count(text_of(page.locator("#result-count"))) or 0) >= 1,
        "dashboard exact search result",
    )

    exact_text = text_of(page.locator("#result-count"))
    exact_count = parse_count(exact_text)
    if exact_count is None or exact_count < 1:
        raise RuntimeError(f"Exact dashboard search should yield at least 1 result, got: {exact_text}")
    row_texts = [t.strip() for t in page.locator("#cve-list .cve-row").all_text_contents()]
    if not any(first_cve in t for t in row_texts):
        raise RuntimeError(f"Searched CVE not present in rendered rows: {first_cve}")

    search_input.fill("")
    wait_for(lambda: parse_count(text_of(page.locator("#result-count"))) == initial_count, "dashboard search reset")

    page.select_option("#severity-filter", "critical")
    wait_for(lambda: parse_count(text_of(page.locator("#result-count"))) is not None, "dashboard severity filter")
    critical_text = text_of(page.locator("#result-count"))
    critical_count = parse_count(critical_text)
    if critical_count is None or critical_count > initial_count:
        raise RuntimeError(f"Severity filter produced invalid dashboard results: {critical_text}")

    page.click("#clear-filters")
    wait_for(lambda: parse_count(text_of(page.locator("#result-count"))) == initial_count, "dashboard clear filters")

    page.select_option("#kev-filter", "only")
    wait_for(lambda: parse_count(text_of(page.locator("#result-count"))) is not None, "dashboard KEV filter")
    kev_text = text_of(page.locator("#result-count"))
    kev_count = parse_count(kev_text)
    if kev_count is None or kev_count > initial_count:
        raise RuntimeError(f"KEV filter produced invalid dashboard results: {kev_text}")
    print(f"[dashboard] exact_count={exact_count}, critical_count={critical_count}, kev_count={kev_count}")

    record(
        "dashboard",
        initial_count=initial_count,
        exact_search=first_cve,
        exact_count=exact_count,
        critical_count=critical_count,
        kev_count=kev_count,
    )


def smoke_news(page) -> None:
    page.goto(f"{BASE_URL}/news.html", wait_until="domcontentloaded")
    wait_for(lambda: page.locator("#news-grid a").count() > 0, "news cards")

    initial_count = page.locator("#news-grid a").count()
    if initial_count < 1:
        raise RuntimeError("News grid did not render any cards")
    print(f"[news] initial_cards={initial_count}")

    first_title = text_of(page.locator("#news-grid a h3").first)
    if not first_title:
        raise RuntimeError("Could not read first news title")

    page.locator("#news-search").fill(first_title)
    wait_for(lambda: page.locator("#news-grid a").count() == 1, "news exact search")
    exact_count = page.locator("#news-grid a").count()
    if exact_count != 1:
        raise RuntimeError(f"Exact news search should yield 1 card, got {exact_count}")

    page.locator("#news-search").fill("")
    wait_for(lambda: page.locator("#news-grid a").count() == initial_count, "news search reset")

    page.select_option("#tier-filter", "4")
    wait_for(lambda: page.locator("#news-grid a").count() >= 0, "news tier filter")
    tier_count = page.locator("#news-grid a").count()
    if tier_count > initial_count:
        raise RuntimeError(f"Tier filter produced invalid card count: {tier_count} > {initial_count}")

    record(
        "news",
        initial_cards=initial_count,
        exact_title=first_title,
        exact_count=exact_count,
        tier_4_count=tier_count,
    )


def smoke_index(page) -> None:
    page.goto(f"{BASE_URL}/index.html", wait_until="domcontentloaded")
    wait_for(lambda: page.locator("#news-feed a").count() > 0, "index news feed")

    feed_count = page.locator("#news-feed a").count()
    first_headline = text_of(page.locator("#news-feed a p.text-xs.font-mono").first)
    if not first_headline:
        raise RuntimeError("Home page news feed headline missing")

    try:
        loading_visible = page.locator("#news-loading").is_visible(timeout=3000)
    except PlaywrightTimeoutError:
        loading_visible = False
    if loading_visible:
        raise RuntimeError("Home page loading state never cleared")

    record("index", feed_count=feed_count, first_headline=first_headline)


def smoke_docs(page) -> None:
    page.goto(f"{BASE_URL}/docs.html", wait_until="domcontentloaded")

    def docs_ready() -> bool:
        values = [
            text_of(page.locator("#active-sensors")),
            text_of(page.locator("#cves-current-year")),
            text_of(page.locator("#critical-cves")),
            text_of(page.locator("#epss-coverage")),
        ]
        return all(v and v != "..." for v in values)

    wait_for(docs_ready, "docs stats")

    stats = {
        "active_sensors": text_of(page.locator("#active-sensors")),
        "cves_current_year": text_of(page.locator("#cves-current-year")),
        "critical_cves": text_of(page.locator("#critical-cves")),
        "epss_coverage": text_of(page.locator("#epss-coverage")),
        "version": text_of(page.locator("#version-badge")),
    }

    if not re.match(r"^v\d+", stats["version"], re.I):
        raise RuntimeError(f"Docs version badge missing or malformed: {stats['version']}")

    record("docs", **stats)


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1200})
        try:
            smoke_dashboard(page)
            smoke_news(page)
            smoke_index(page)
            smoke_docs(page)
            summary["status"] = "pass"
            summary["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            OUT_FILE.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            print(f"PASS {OUT_FILE}")
            return 0
        except Exception as exc:
            summary["status"] = "fail"
            summary["error"] = str(exc)
            summary["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            OUT_FILE.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            print(f"FAIL {exc}", file=sys.stderr)
            try:
                page.screenshot(path=str(FAILSHOT), full_page=True)
            except Exception:
                pass
            return 1
        finally:
            page.close()
            browser.close()


if __name__ == "__main__":
    raise SystemExit(main())
