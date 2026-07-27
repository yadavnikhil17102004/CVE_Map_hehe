#!/usr/bin/env python3
"""Phase 5 verifier: compare JSON safety-net outputs vs Postgres dual-write data.

Scope rules:
- Compare only years that have JSON counterparts on disk.
- Do not treat historical-only Postgres years (from Phase 4B) as mismatches.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import psycopg2
import psycopg2.extras

YEAR_FILE_RE = re.compile(r"^(\d{4})\.json$")
NVD_YEAR_FILE_RE = re.compile(r"^nvd_intel_(\d{4})\.json$")


@dataclass
class CompareSummary:
    checked: int = 0
    missing_in_db: int = 0
    extra_in_db: int = 0
    field_mismatches: int = 0

    @property
    def ok(self) -> bool:
        # Archival semantics: JSON must be represented in DB.
        # DB-only rows are informational/history, not failure.
        return self.missing_in_db == 0 and self.field_mismatches == 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Verify JSON vs Postgres dual-write consistency")
    p.add_argument("--data-dir", default="data")
    p.add_argument("--host", default=os.getenv("POSTGRES_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("POSTGRES_PORT", "5432")))
    p.add_argument("--dbname", default=os.getenv("POSTGRES_DB"))
    p.add_argument("--user", default=os.getenv("POSTGRES_USER"))
    p.add_argument("--password", default=os.getenv("POSTGRES_PASSWORD"))
    p.add_argument("--sample-limit", type=int, default=25, help="Max mismatch samples per section")
    p.add_argument("--output", default="", help="Optional JSON output path")
    p.add_argument("--label", default="baseline", help="Run label (for logging/reporting)")
    p.add_argument("--strict", action="store_true", help="Exit non-zero on mismatches")
    return p.parse_args()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def norm_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def norm_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v in (None, "", 0, "0", "false", "False", "FALSE"):
        return False
    return True


def norm_float(v: Any) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return round(float(v), 6)
    except Exception:
        return None


def norm_date(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, date):
        return v.isoformat()
    s = str(v).strip()
    if not s:
        return ""
    # handle timestamps by date-prefix
    if len(s) >= 10 and s[4] == "-" and s[7] == "-":
        return s[:10]
    return s


def norm_topics(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            if isinstance(parsed, list):
                v = parsed
            else:
                return []
        except Exception:
            return []
    if not isinstance(v, list):
        return []
    out = [norm_str(x) for x in v if norm_str(x)]
    return sorted(set(out))


def norm_products(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            if isinstance(parsed, list):
                v = parsed
            else:
                return []
        except Exception:
            return []
    if not isinstance(v, list):
        return []
    out = [norm_str(x) for x in v if norm_str(x)]
    return sorted(out)


def to_jsonable(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_jsonable(x) for x in obj]
    return obj


def chunked(seq: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def collect_year_files(data_dir: Path) -> List[int]:
    years: List[int] = []
    for p in data_dir.iterdir():
        m = YEAR_FILE_RE.match(p.name)
        if m:
            years.append(int(m.group(1)))
    return sorted(years)


def collect_nvd_year_files(data_dir: Path) -> List[int]:
    years: List[int] = []
    for p in data_dir.iterdir():
        m = NVD_YEAR_FILE_RE.match(p.name)
        if m:
            years.append(int(m.group(1)))
    return sorted(years)


def compare_cve_repos(
    cur: psycopg2.extensions.cursor,
    data_dir: Path,
    sample_limit: int,
) -> Dict[str, Any]:
    years = collect_year_files(data_dir)
    summary = CompareSummary()
    samples: List[Dict[str, Any]] = []
    per_year: Dict[int, Dict[str, int]] = {}

    for year in years:
        payload = load_json(data_dir / f"{year}.json")
        cves = payload.get("cves", [])
        json_map: Dict[Tuple[str, int], Dict[str, Any]] = {}

        for cve in cves:
            cve_id = norm_str(cve.get("cve_id"))
            for repo in cve.get("repositories", []) or []:
                rid = int(repo.get("id"))
                key = (cve_id, rid)
                owner = repo.get("owner") or {}
                json_map[key] = {
                    "repo_name": norm_str(repo.get("name")),
                    "full_name": norm_str(repo.get("full_name")),
                    "repo_url": norm_str(repo.get("html_url")),
                    "description": norm_str(repo.get("description")),
                    "stargazers_count": int(repo.get("stargazers_count") or 0),
                    "forks_count": int(repo.get("forks_count") or 0),
                    "language": norm_str(repo.get("language")),
                    "topics": norm_topics(repo.get("topics")),
                    "owner_login": norm_str(owner.get("login")),
                    "owner_html_url": norm_str(owner.get("html_url")),
                    "clone_url": norm_str(repo.get("clone_url")),
                    "has_code": norm_bool(repo.get("has_code")),
                    "age_days": int(repo.get("age_days") or 0),
                }

        cur.execute(
            """
            SELECT cve_id, repo_id, repo_name, full_name, repo_url, description,
                   stargazers_count, forks_count, language, topics,
                   owner_login, owner_html_url, clone_url, has_code, age_days
            FROM cve_repos
            WHERE year = %s
            """,
            (year,),
        )
        db_rows = cur.fetchall()
        db_map: Dict[Tuple[str, int], Dict[str, Any]] = {}
        for r in db_rows:
            key = (norm_str(r["cve_id"]), int(r["repo_id"]))
            db_map[key] = {
                "repo_name": norm_str(r["repo_name"]),
                "full_name": norm_str(r["full_name"]),
                "repo_url": norm_str(r["repo_url"]),
                "description": norm_str(r["description"]),
                "stargazers_count": int(r["stargazers_count"] or 0),
                "forks_count": int(r["forks_count"] or 0),
                "language": norm_str(r["language"]),
                "topics": norm_topics(r["topics"]),
                "owner_login": norm_str(r["owner_login"]),
                "owner_html_url": norm_str(r["owner_html_url"]),
                "clone_url": norm_str(r["clone_url"]),
                "has_code": norm_bool(r["has_code"]),
                "age_days": int(r["age_days"] or 0),
            }

        json_keys = set(json_map)
        db_keys = set(db_map)
        miss = sorted(json_keys - db_keys)
        extra = sorted(db_keys - json_keys)
        mism = 0
        for key in sorted(json_keys & db_keys):
            if json_map[key] != db_map[key]:
                mism += 1
                if len(samples) < sample_limit:
                    samples.append(
                        {
                            "table": "cve_repos",
                            "year": year,
                            "key": {"cve_id": key[0], "repo_id": key[1]},
                            "json": json_map[key],
                            "db": db_map[key],
                        }
                    )

        if len(samples) < sample_limit:
            for key in miss[: max(0, sample_limit - len(samples))]:
                samples.append({"table": "cve_repos", "year": year, "missing_in_db": {"cve_id": key[0], "repo_id": key[1]}})
        if len(samples) < sample_limit:
            for key in extra[: max(0, sample_limit - len(samples))]:
                samples.append({"table": "cve_repos", "year": year, "extra_in_db": {"cve_id": key[0], "repo_id": key[1]}})

        summary.checked += len(json_keys)
        summary.missing_in_db += len(miss)
        summary.extra_in_db += len(extra)
        summary.field_mismatches += mism
        per_year[year] = {
            "json_rows": len(json_keys),
            "db_rows": len(db_keys),
            "missing_in_db": len(miss),
            "extra_in_db": len(extra),
            "field_mismatches": mism,
        }

    return {
        "years_compared": years,
        "summary": summary.__dict__,
        "ok": summary.ok,
        "per_year": per_year,
        "samples": samples,
    }


def compare_nvd(
    cur: psycopg2.extensions.cursor,
    data_dir: Path,
    sample_limit: int,
) -> Dict[str, Any]:
    years = collect_nvd_year_files(data_dir)
    summary = CompareSummary()
    samples: List[Dict[str, Any]] = []
    per_year: Dict[int, Dict[str, int]] = {}
    historical_only_years = []  # informational, not mismatch

    cur.execute("SELECT DISTINCT year FROM nvd_intel ORDER BY year")
    db_years = sorted([int(r["year"]) for r in cur.fetchall() if r.get("year") is not None])
    json_year_set = set(years)
    historical_only_years = [y for y in db_years if y not in json_year_set]

    for year in years:
        payload = load_json(data_dir / f"nvd_intel_{year}.json")
        json_map: Dict[str, Dict[str, Any]] = {}
        for cve_id, intel in payload.items():
            json_map[norm_str(cve_id)] = {
                "s": norm_float(intel.get("s")),
                "v": norm_str(intel.get("v")),
                "d": norm_str(intel.get("d")),
                "c": norm_str(intel.get("c")),
                "w": norm_str(intel.get("w")),
                "k": norm_bool(intel.get("k")),
                "r": norm_str(intel.get("r")),
                "p": norm_date(intel.get("p")),
                "u": norm_str(intel.get("u")),
                "e": norm_float(intel.get("e")),
                "q": norm_products(intel.get("q")),
            }

        db_map: Dict[str, Dict[str, Any]] = {}
        cve_ids = sorted(json_map.keys())
        for batch in chunked(cve_ids, 1000):
            cur.execute(
                """
                SELECT cve_id, cvss_score, severity, description, cvss_vector, cwe,
                       kev_flag, source, published_date, status, epss_score, products
                FROM nvd_intel
                WHERE cve_id = ANY(%s)
                """,
                (batch,),
            )
            for r in cur.fetchall():
                cve_id = norm_str(r["cve_id"])
                db_map[cve_id] = {
                    "s": norm_float(r["cvss_score"]),
                    "v": norm_str(r["severity"]),
                    "d": norm_str(r["description"]),
                    "c": norm_str(r["cvss_vector"]),
                    "w": norm_str(r["cwe"]),
                    "k": norm_bool(r["kev_flag"]),
                    "r": norm_str(r["source"]),
                    "p": norm_date(r["published_date"]),
                    "u": norm_str(r["status"]),
                    "e": norm_float(r["epss_score"]),
                    "q": norm_products(r["products"]),
                }

        json_keys = set(json_map)
        db_keys = set(db_map)
        miss = sorted(json_keys - db_keys)
        extra = sorted(db_keys - json_keys)  # should be 0 because we query by json keys
        mism = 0
        epss_drift = 0
        for key in sorted(json_keys & db_keys):
            equal, only_epss_drift = nvd_row_equal(json_map[key], db_map[key])
            if not equal:
                mism += 1
                if len(samples) < sample_limit:
                    samples.append(
                        {"table": "nvd_intel", "year": year, "cve_id": key, "json": json_map[key], "db": db_map[key]}
                    )
            elif only_epss_drift:
                epss_drift += 1

        if len(samples) < sample_limit:
            for key in miss[: max(0, sample_limit - len(samples))]:
                samples.append({"table": "nvd_intel", "year": year, "missing_in_db": {"cve_id": key}})

        summary.checked += len(json_keys)
        summary.missing_in_db += len(miss)
        summary.extra_in_db += len(extra)
        summary.field_mismatches += mism
        per_year[year] = {
            "json_rows": len(json_keys),
            "db_rows_for_json_keys": len(db_keys),
            "missing_in_db": len(miss),
            "extra_in_db": len(extra),
            "field_mismatches": mism,
            "epss_score_drift_only": epss_drift,
        }

    return {
        "years_compared": years,
        "historical_only_years_in_db": historical_only_years,
        "summary": summary.__dict__,
        "ok": summary.ok,
        "per_year": per_year,
        "samples": samples,
    }


def nvd_row_equal(a: Dict[str, Any], b: Dict[str, Any]) -> Tuple[bool, bool]:
    only_epss_drift = False
    for k in a.keys():
        av = a.get(k)
        bv = b.get(k)
        if k == "e":
            # EPSS can be absent in JSON but represented as numeric 0 in DB after
            # historical enrichment/upsert paths; treat these as equivalent.
            if (av is None and bv == 0.0) or (bv is None and av == 0.0):
                continue
            # EPSS score is time-variant and may drift between JSON snapshot and DB
            # state when updates are not perfectly simultaneous. Track drift but do
            # not fail archival subset verification on this field alone.
            if av is not None and bv is not None and av != bv:
                only_epss_drift = True
                continue
        if av != bv:
            return False, False
    return True, only_epss_drift


def compare_news(
    cur: psycopg2.extensions.cursor,
    data_dir: Path,
    sample_limit: int,
) -> Dict[str, Any]:
    summary = CompareSummary()
    samples: List[Dict[str, Any]] = []
    news_path = data_dir / "news.json"
    if not news_path.exists():
        return {"summary": summary.__dict__, "ok": True, "samples": samples, "note": "data/news.json not found"}

    payload = load_json(news_path)
    json_map: Dict[str, Dict[str, Any]] = {}
    for a in payload.get("articles", []):
        link = norm_str(a.get("link"))
        if not link:
            continue
        json_map[link] = {
            "title": norm_str(a.get("title")),
            "source": norm_str(a.get("source")),
            "tier": norm_str(a.get("tier")),
            "description": norm_str(a.get("description")),
            "image_url": norm_str(a.get("image_url")),
            "pub_date_raw": norm_str(a.get("pub_date")),
        }

    links = sorted(json_map.keys())
    db_map: Dict[str, Dict[str, Any]] = {}
    for batch in chunked(links, 1000):
        cur.execute(
            """
            SELECT link, title, source, tier, description, image_url, pub_date_raw
            FROM news_items
            WHERE link = ANY(%s)
            """,
            (batch,),
        )
        for r in cur.fetchall():
            link = norm_str(r["link"])
            db_map[link] = {
                "title": norm_str(r["title"]),
                "source": norm_str(r["source"]),
                "tier": norm_str(r["tier"]),
                "description": norm_str(r["description"]),
                "image_url": norm_str(r["image_url"]),
                "pub_date_raw": norm_str(r["pub_date_raw"]),
            }

    json_keys = set(json_map)
    db_keys = set(db_map)
    miss = sorted(json_keys - db_keys)
    extra = sorted(db_keys - json_keys)
    mism = 0
    for key in sorted(json_keys & db_keys):
        if json_map[key] != db_map[key]:
            mism += 1
            if len(samples) < sample_limit:
                samples.append({"table": "news_items", "link": key, "json": json_map[key], "db": db_map[key]})

    if len(samples) < sample_limit:
        for key in miss[: max(0, sample_limit - len(samples))]:
            samples.append({"table": "news_items", "missing_in_db": {"link": key}})
    if len(samples) < sample_limit:
        for key in extra[: max(0, sample_limit - len(samples))]:
            samples.append({"table": "news_items", "extra_in_db": {"link": key}})

    summary.checked = len(json_keys)
    summary.missing_in_db = len(miss)
    summary.extra_in_db = len(extra)
    summary.field_mismatches = mism

    return {"summary": summary.__dict__, "ok": summary.ok, "samples": samples}


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"[!] data dir not found: {data_dir}", file=sys.stderr)
        return 2
    if not (args.dbname and args.user and args.password):
        print("[!] missing db params (dbname/user/password)", file=sys.stderr)
        return 2

    conn = psycopg2.connect(
        host=args.host,
        port=args.port,
        dbname=args.dbname,
        user=args.user,
        password=args.password,
    )
    report: Dict[str, Any] = {"label": args.label, "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z")}

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            report["cve_repos"] = compare_cve_repos(cur, data_dir, args.sample_limit)
            report["nvd_intel"] = compare_nvd(cur, data_dir, args.sample_limit)
            report["news_items"] = compare_news(cur, data_dir, args.sample_limit)
    finally:
        conn.close()

    overall_ok = bool(report["cve_repos"]["ok"] and report["nvd_intel"]["ok"] and report["news_items"]["ok"])
    report["overall_ok"] = overall_ok

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(to_jsonable(report), f, indent=2, sort_keys=True)
            f.write("\n")

    # concise human-readable summary
    def _line(name: str, obj: Dict[str, Any]) -> str:
        s = obj["summary"]
        return (
            f"{name}: checked={s['checked']:,} missing_in_db={s['missing_in_db']:,} "
            f"extra_in_db={s['extra_in_db']:,} field_mismatches={s['field_mismatches']:,} ok={obj['ok']}"
        )

    print(f"[verify:{args.label}] overall_ok={overall_ok}")
    print(_line("cve_repos", report["cve_repos"]))
    print(_line("nvd_intel", report["nvd_intel"]))
    print(_line("news_items", report["news_items"]))
    print("note: extra_in_db is informational under archival semantics (JSON subset enforced).")
    if report["nvd_intel"].get("historical_only_years_in_db"):
        years = report["nvd_intel"]["historical_only_years_in_db"]
        print(f"nvd_intel historical-only DB years (expected, no JSON counterpart): {years[0]}..{years[-1]} ({len(years)} years)")

    if args.strict and not overall_ok:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
