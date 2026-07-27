#!/usr/bin/env python3
"""One-time JSON -> Postgres backfill for CVE-Intel.

Usage:
  python3 scripts/migration/migrate.py \
    --data-dir ./data \
    --host 127.0.0.1 --port 5432 --dbname cveintel --user cveintel --password '...'
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, date, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import psycopg2
import psycopg2.extras

YEAR_FILE_RE = re.compile(r"^(\d{4})\.json$")
NVD_YEAR_FILE_RE = re.compile(r"^nvd_intel_(\d{4})\.json$")
CVE_YEAR_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.IGNORECASE)


@dataclass
class UpsertStats:
    inserted: int = 0
    updated: int = 0

    @property
    def total(self) -> int:
        return self.inserted + self.updated

    def add(self, inserted: int, updated: int) -> None:
        self.inserted += inserted
        self.updated += updated


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Backfill JSON data into Postgres")
    p.add_argument("--data-dir", default="data", help="Directory containing JSON data files")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=5432)
    p.add_argument("--dbname", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--batch-size", type=int, default=1000)
    return p.parse_args()


def chunks(seq: List[Tuple[Any, ...]], n: int) -> Iterable[List[Tuple[Any, ...]]]:
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def parse_iso_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def parse_date(d: Optional[str]) -> Optional[date]:
    if not d:
        return None
    try:
        return date.fromisoformat(d)
    except Exception:
        return None


def parse_pub_date(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        # fallback for potential RFC3339 values
        return parse_iso_ts(raw)


def year_from_cve(cve_id: str) -> Optional[int]:
    m = CVE_YEAR_RE.match(cve_id)
    if not m:
        return None
    return int(m.group(1))


def upsert_cve_repos(cur, rows: List[Tuple[Any, ...]], batch_size: int) -> UpsertStats:
    stats = UpsertStats()
    if not rows:
        return stats

    sql = """
    INSERT INTO cve_repos (
      cve_id, year, repo_id, repo_name, full_name, repo_url, description,
      stargazers_count, forks_count, language, updated_at, pushed_at, created_at,
      topics, owner_login, owner_html_url, clone_url, has_code, age_days
    ) VALUES %s
    ON CONFLICT (cve_id, repo_id) DO UPDATE SET
      year = EXCLUDED.year,
      repo_name = EXCLUDED.repo_name,
      full_name = EXCLUDED.full_name,
      repo_url = EXCLUDED.repo_url,
      description = EXCLUDED.description,
      stargazers_count = EXCLUDED.stargazers_count,
      forks_count = EXCLUDED.forks_count,
      language = EXCLUDED.language,
      updated_at = EXCLUDED.updated_at,
      pushed_at = EXCLUDED.pushed_at,
      created_at = EXCLUDED.created_at,
      topics = EXCLUDED.topics,
      owner_login = EXCLUDED.owner_login,
      owner_html_url = EXCLUDED.owner_html_url,
      clone_url = EXCLUDED.clone_url,
      has_code = EXCLUDED.has_code,
      age_days = EXCLUDED.age_days,
      discovered_at = NOW()
    RETURNING (xmax = 0) AS inserted;
    """

    for batch in chunks(rows, batch_size):
        psycopg2.extras.execute_values(cur, sql, batch, page_size=batch_size)
        res = cur.fetchall()
        inserted = sum(1 for r in res if r[0])
        updated = len(res) - inserted
        stats.add(inserted, updated)

    return stats


def upsert_nvd_intel(cur, rows: List[Tuple[Any, ...]], batch_size: int) -> UpsertStats:
    stats = UpsertStats()
    if not rows:
        return stats

    sql = """
    INSERT INTO nvd_intel (
      cve_id, year, cvss_score, severity, description, cvss_vector,
      cwe, kev_flag, source, published_date, status, epss_score, products, updated_at
    ) VALUES %s
    ON CONFLICT (cve_id) DO UPDATE SET
      year = EXCLUDED.year,
      cvss_score = EXCLUDED.cvss_score,
      severity = EXCLUDED.severity,
      description = EXCLUDED.description,
      cvss_vector = EXCLUDED.cvss_vector,
      cwe = EXCLUDED.cwe,
      kev_flag = EXCLUDED.kev_flag,
      source = EXCLUDED.source,
      published_date = EXCLUDED.published_date,
      status = EXCLUDED.status,
      epss_score = EXCLUDED.epss_score,
      products = EXCLUDED.products,
      updated_at = NOW()
    RETURNING (xmax = 0) AS inserted;
    """

    for batch in chunks(rows, batch_size):
        psycopg2.extras.execute_values(cur, sql, batch, page_size=batch_size)
        res = cur.fetchall()
        inserted = sum(1 for r in res if r[0])
        updated = len(res) - inserted
        stats.add(inserted, updated)

    return stats


def upsert_news_items(cur, rows: List[Tuple[Any, ...]], batch_size: int) -> UpsertStats:
    stats = UpsertStats()
    if not rows:
        return stats

    sql = """
    INSERT INTO news_items (
      title, link, source, tier, description, image_url,
      pub_date_raw, published_at, last_updated
    ) VALUES %s
    ON CONFLICT (link) DO UPDATE SET
      title = EXCLUDED.title,
      source = EXCLUDED.source,
      tier = EXCLUDED.tier,
      description = EXCLUDED.description,
      image_url = EXCLUDED.image_url,
      pub_date_raw = EXCLUDED.pub_date_raw,
      published_at = EXCLUDED.published_at,
      last_updated = EXCLUDED.last_updated,
      ingested_at = NOW()
    RETURNING (xmax = 0) AS inserted;
    """

    for batch in chunks(rows, batch_size):
        psycopg2.extras.execute_values(cur, sql, batch, page_size=batch_size)
        res = cur.fetchall()
        inserted = sum(1 for r in res if r[0])
        updated = len(res) - inserted
        stats.add(inserted, updated)

    return stats


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def collect_cve_repo_rows(data_dir: Path) -> Tuple[List[Tuple[Any, ...]], Dict[int, int]]:
    rows: List[Tuple[Any, ...]] = []
    per_year_counts: Dict[int, int] = {}

    for file in sorted(data_dir.iterdir()):
        m = YEAR_FILE_RE.match(file.name)
        if not m:
            continue
        year = int(m.group(1))
        payload = load_json(file)
        cves = payload.get("cves", [])
        per_year_counts[year] = len(cves)

        for cve in cves:
            cve_id = cve.get("cve_id")
            repos = cve.get("repositories", [])
            for repo in repos:
                owner = repo.get("owner") or {}
                rows.append(
                    (
                        cve_id,
                        year,
                        repo.get("id"),
                        repo.get("name"),
                        repo.get("full_name"),
                        repo.get("html_url"),
                        repo.get("description"),
                        repo.get("stargazers_count"),
                        repo.get("forks_count"),
                        repo.get("language"),
                        parse_iso_ts(repo.get("updated_at")),
                        parse_iso_ts(repo.get("pushed_at")),
                        parse_iso_ts(repo.get("created_at")),
                        json.dumps(repo.get("topics", [])),
                        owner.get("login"),
                        owner.get("html_url"),
                        repo.get("clone_url"),
                        repo.get("has_code"),
                        repo.get("age_days"),
                    )
                )

    return rows, per_year_counts


def collect_nvd_rows(data_dir: Path) -> Tuple[List[Tuple[Any, ...]], Dict[str, int]]:
    # Map cve_id -> compact intel object, prefer year files then fill missing from full file.
    merged: Dict[str, Dict[str, Any]] = {}
    source_counts = {"year_files": 0, "full_file_missing_only": 0}

    year_files = sorted([p for p in data_dir.iterdir() if NVD_YEAR_FILE_RE.match(p.name)])
    for yf in year_files:
        data = load_json(yf)
        for cve_id, intel in data.items():
            merged[cve_id] = intel
            source_counts["year_files"] += 1

    full_file = data_dir / "nvd_intel.json"
    if full_file.exists():
        full_data = load_json(full_file)
        for cve_id, intel in full_data.items():
            if cve_id not in merged:
                merged[cve_id] = intel
                source_counts["full_file_missing_only"] += 1

    rows: List[Tuple[Any, ...]] = []

    for cve_id, intel in merged.items():
        year = year_from_cve(cve_id)
        if year is None:
            continue

        # Compact key mapping from JSON:
        # s=cvss_score, v=severity, d=description, c=cvss_vector, w=cwe,
        # k=kev_flag, r=source, p=published_date, u=status, e=epss_score, q=products
        rows.append(
            (
                cve_id,
                year,
                intel.get("s"),
                intel.get("v"),
                intel.get("d"),
                intel.get("c"),
                intel.get("w"),
                bool(intel.get("k", False)),
                intel.get("r"),
                parse_date(intel.get("p")),
                intel.get("u"),
                intel.get("e"),
                json.dumps(intel.get("q", [])),
                datetime.now(timezone.utc),
            )
        )

    return rows, source_counts


def collect_news_rows(data_dir: Path) -> List[Tuple[Any, ...]]:
    news_file = data_dir / "news.json"
    if not news_file.exists():
        return []

    payload = load_json(news_file)
    last_updated = parse_iso_ts(payload.get("last_updated"))

    rows: List[Tuple[Any, ...]] = []
    for item in payload.get("articles", []):
        raw_pub = item.get("pub_date")
        rows.append(
            (
                item.get("title"),
                item.get("link"),
                item.get("source"),
                item.get("tier"),
                item.get("description"),
                item.get("image_url"),
                raw_pub,
                parse_pub_date(raw_pub),
                last_updated,
            )
        )
    return rows


def main() -> None:
    args = parse_args()
    data_dir = Path(args.data_dir)

    if not data_dir.exists():
        raise SystemExit(f"data directory not found: {data_dir}")

    print("[i] Collecting rows from JSON files...")
    cve_rows, cve_year_counts = collect_cve_repo_rows(data_dir)
    nvd_rows, nvd_sources = collect_nvd_rows(data_dir)
    news_rows = collect_news_rows(data_dir)

    print(f"[i] CVE repo rows prepared: {len(cve_rows):,}")
    print(f"[i] NVD rows prepared: {len(nvd_rows):,} (from year files: {nvd_sources['year_files']:,}, full-file-only additions: {nvd_sources['full_file_missing_only']:,})")
    print(f"[i] News rows prepared: {len(news_rows):,}")

    conn = psycopg2.connect(
        host=args.host,
        port=args.port,
        dbname=args.dbname,
        user=args.user,
        password=args.password,
    )

    try:
        with conn:
            with conn.cursor() as cur:
                cve_stats = upsert_cve_repos(cur, cve_rows, args.batch_size)
                nvd_stats = upsert_nvd_intel(cur, nvd_rows, args.batch_size)
                news_stats = upsert_news_items(cur, news_rows, args.batch_size)

        print("\n=== Migration Summary ===")
        print(f"cve_repos: inserted={cve_stats.inserted:,} updated={cve_stats.updated:,} total_upserted={cve_stats.total:,}")
        print(f"nvd_intel: inserted={nvd_stats.inserted:,} updated={nvd_stats.updated:,} total_upserted={nvd_stats.total:,}")
        print(f"news_items: inserted={news_stats.inserted:,} updated={news_stats.updated:,} total_upserted={news_stats.total:,}")

        print("\n=== Source Snapshot ===")
        if cve_year_counts:
            years_sorted = sorted(cve_year_counts)
            print(f"cve_year_files: {years_sorted[0]}..{years_sorted[-1]} ({len(years_sorted)} files)")
            print(f"cve_entries_total: {sum(cve_year_counts.values()):,}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
