#!/usr/bin/env python3
"""Phase 4B historical NVD metadata backfill (2000-present), resumable.

- Pulls NVD API 2.0 in 120-day published-date windows.
- Enriches EPSS from FIRST bulk CSV (.csv.gz).
- Upserts extended metadata into nvd_intel.
- Persists checkpoint in Postgres (nvd_backfill_checkpoint).
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import os
import sys
import tempfile
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import psycopg2
import psycopg2.extras

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BULK_URLS = [
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
]
WINDOW_DAYS = 120
NVD_PAGE_SIZE = 2000


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Historical NVD backfill")
    p.add_argument("--host", default=os.getenv("POSTGRES_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("POSTGRES_PORT", "5432")))
    p.add_argument("--dbname", default=os.getenv("POSTGRES_DB"))
    p.add_argument("--user", default=os.getenv("POSTGRES_USER"))
    p.add_argument("--password", default=os.getenv("POSTGRES_PASSWORD"))
    p.add_argument("--nvd-api-key", default=os.getenv("NVD_API_KEY"))
    p.add_argument("--start-date", default="2000-01-01")
    p.add_argument("--end-date", default=date.today().isoformat())
    p.add_argument("--window-days", type=int, default=WINDOW_DAYS)
    p.add_argument("--rate-sleep", type=float, default=0.65)
    p.add_argument("--log-level", default="INFO")
    p.add_argument("--status-file", default="/var/log/cveintel/backfill_status.json")
    return p.parse_args()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)sZ %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_iso_dt(v: str) -> datetime:
    return utc(datetime.fromisoformat(v.replace("Z", "+00:00")))


def fmt_nvd_ts(dt: datetime) -> str:
    dt = utc(dt)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def year_from_cve(cve_id: str) -> Optional[int]:
    try:
        if not cve_id.startswith("CVE-"):
            return None
        return int(cve_id.split("-")[1])
    except Exception:
        return None


def fetch_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 60, retries: int = 5) -> Dict[str, Any]:
    last_err: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            req = Request(url, headers=headers or {})
            with urlopen(req, timeout=timeout) as r:  # nosec B310
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:
            last_err = e
            sleep_s = min(60, 2**attempt)
            logging.warning("request failed (attempt %d/%d): %s; sleeping %ss", attempt, retries, e, sleep_s)
            time.sleep(sleep_s)
    raise RuntimeError(f"request failed after retries: {last_err}")


def load_epss_bulk() -> Dict[str, Tuple[Optional[float], Optional[float]]]:
    data = None
    for epss_url in EPSS_BULK_URLS:
        try:
            logging.info("loading EPSS bulk CSV: %s", epss_url)
            req = Request(epss_url)
            with urlopen(req, timeout=180) as r:  # nosec B310
                data = r.read()
            break
        except Exception as e:
            logging.warning("failed EPSS URL %s: %s", epss_url, e)
    if data is None:
        raise RuntimeError("unable to download EPSS bulk CSV from configured URLs")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        text = gz.read().decode("utf-8", errors="replace")

    out: Dict[str, Tuple[Optional[float], Optional[float]]] = {}
    # FIRST bulk CSV often starts with metadata comment like:
    # "#model_version:...,score_date:..."
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    for row in reader:
        cve = (row.get("cve") or "").strip().upper()
        if not cve:
            continue
        epss = row.get("epss")
        perc = row.get("percentile")
        epss_f = float(epss) if epss else None
        perc_f = float(perc) if perc else None
        out[cve] = (epss_f, perc_f)

    logging.info("loaded %d EPSS rows", len(out))
    return out


def metric_value(metrics: Dict[str, Any], key: str) -> Tuple[Optional[float], Optional[str], Optional[str], Optional[str]]:
    arr = metrics.get(key) or []
    if not arr:
        return None, None, None, None

    preferred = None
    for m in arr:
        if m.get("type") == "Primary":
            preferred = m
            break
    if preferred is None:
        preferred = arr[0]

    data = preferred.get("cvssData") or {}
    score = data.get("baseScore")
    vector = data.get("vectorString")
    severity = data.get("baseSeverity") or preferred.get("baseSeverity")
    source = preferred.get("source")
    return score, vector, severity, source


def pick_primary_cwe(weaknesses: List[Dict[str, Any]]) -> Optional[str]:
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value")
            if d.get("lang") == "en" and val and val not in {"NVD-CWE-noinfo", "NVD-CWE-Other"}:
                return val
    return None


def english_description(descs: List[Dict[str, Any]]) -> str:
    for d in descs:
        if d.get("lang") == "en" and d.get("value"):
            return d["value"]
    return "No description available."


def upsert_batch(cur, rows: List[Tuple[Any, ...]]) -> None:
    if not rows:
        return
    sql = """
    INSERT INTO nvd_intel (
      cve_id, year, cvss_score, severity, description, cvss_vector,
      cwe, kev_flag, source, published_date, status, epss_score, products,
      updated_at,
      cvss_v31_score, cvss_v31_vector, cvss_v31_severity,
      cvss_v30_score, cvss_v30_vector, cvss_v30_severity,
      cvss_v2_score, cvss_v2_vector, cvss_v2_severity,
      nvd_references, cpe_configurations, weaknesses, vendor_comments,
      source_identifier, vuln_status, last_modified_date, epss_percentile
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
      updated_at = NOW(),
      cvss_v31_score = EXCLUDED.cvss_v31_score,
      cvss_v31_vector = EXCLUDED.cvss_v31_vector,
      cvss_v31_severity = EXCLUDED.cvss_v31_severity,
      cvss_v30_score = EXCLUDED.cvss_v30_score,
      cvss_v30_vector = EXCLUDED.cvss_v30_vector,
      cvss_v30_severity = EXCLUDED.cvss_v30_severity,
      cvss_v2_score = EXCLUDED.cvss_v2_score,
      cvss_v2_vector = EXCLUDED.cvss_v2_vector,
      cvss_v2_severity = EXCLUDED.cvss_v2_severity,
      nvd_references = EXCLUDED.nvd_references,
      cpe_configurations = EXCLUDED.cpe_configurations,
      weaknesses = EXCLUDED.weaknesses,
      vendor_comments = EXCLUDED.vendor_comments,
      source_identifier = EXCLUDED.source_identifier,
      vuln_status = EXCLUDED.vuln_status,
      last_modified_date = EXCLUDED.last_modified_date,
      epss_percentile = EXCLUDED.epss_percentile
    """
    psycopg2.extras.execute_values(cur, sql, rows, page_size=500)


def load_checkpoint(cur, default_start: datetime, default_end: datetime) -> Tuple[datetime, datetime, int, int]:
    cur.execute(
        "SELECT window_start, window_end, start_index, processed_cves FROM nvd_backfill_checkpoint WHERE id = 1"
    )
    row = cur.fetchone()
    if not row:
        cur.execute(
            """
            INSERT INTO nvd_backfill_checkpoint (id, window_start, window_end, start_index, processed_cves, status)
            VALUES (1, %s, %s, 0, 0, 'running')
            """,
            (default_start, default_end),
        )
        return default_start, default_end, 0, 0
    return utc(row[0]), utc(row[1]), int(row[2]), int(row[3])


def save_checkpoint(cur, ws: datetime, we: datetime, start_index: int, processed: int, status: str = "running") -> None:
    cur.execute(
        """
        UPDATE nvd_backfill_checkpoint
        SET window_start=%s, window_end=%s, start_index=%s, processed_cves=%s, updated_at=NOW(), status=%s
        WHERE id=1
        """,
        (ws, we, start_index, processed, status),
    )


def safe_write_json(path: str, payload: Dict[str, Any]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".backfill_status.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def rows_total(cur) -> int:
    cur.execute("SELECT COUNT(*) FROM nvd_intel")
    return int(cur.fetchone()[0])


def failed_runs_last_24h(cur) -> int:
    cur.execute(
        """
        SELECT COUNT(*)
        FROM nvd_backfill_runs
        WHERE status = 'failed' AND started_at >= NOW() - INTERVAL '24 hours'
        """
    )
    return int(cur.fetchone()[0])


def estimate_years_remaining(ws: datetime, end_dt: datetime) -> str:
    if ws.date() > end_dt.date():
        return "none"
    return f"{ws.year}-{end_dt.year}"


def emit_status(
    *,
    status_file: str,
    status: str,
    ws: datetime,
    we: datetime,
    processed: int,
    nvd_rows: int,
    epss_loaded: int,
    errors_last_24h: int,
    end_dt: datetime,
    error_message: Optional[str] = None,
) -> None:
    payload: Dict[str, Any] = {
        "last_updated": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "current_window_start": ws.date().isoformat(),
        "current_window_end": we.date().isoformat(),
        "processed_cves_total": processed,
        "nvd_intel_row_count": nvd_rows,
        "epss_rows_loaded": epss_loaded,
        "status": status,
        "errors_last_24h": errors_last_24h,
        "estimated_years_remaining": estimate_years_remaining(ws, end_dt),
    }
    if error_message:
        payload["error"] = error_message[:1000]
    safe_write_json(status_file, payload)


def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)

    missing = []
    for k, v in (
        ("POSTGRES_DB/--dbname", args.dbname),
        ("POSTGRES_USER/--user", args.user),
        ("POSTGRES_PASSWORD/--password", args.password),
        ("NVD_API_KEY/--nvd-api-key", args.nvd_api_key),
    ):
        if not v:
            missing.append(k)
    if missing:
        raise SystemExit(f"missing required configuration: {', '.join(missing)}")

    start_dt = utc(datetime.fromisoformat(args.start_date + "T00:00:00+00:00"))
    end_dt = utc(datetime.fromisoformat(args.end_date + "T23:59:59+00:00"))

    epss_map = load_epss_bulk()
    epss_loaded = len(epss_map)

    conn = psycopg2.connect(
        host=args.host,
        port=args.port,
        dbname=args.dbname,
        user=args.user,
        password=args.password,
    )
    conn.autocommit = False

    run_id = None
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO nvd_backfill_runs (status, note) VALUES ('running', %s) RETURNING id",
                (f"range={args.start_date}..{args.end_date}",),
            )
            run_id = cur.fetchone()[0]
            conn.commit()

        with conn.cursor() as cur:
            ws_default = start_dt
            we_default = min(end_dt, ws_default + timedelta(days=args.window_days) - timedelta(seconds=1))
            ws, we, start_index, processed = load_checkpoint(cur, ws_default, we_default)
            conn.commit()

        headers = {"Accept": "application/json", "apiKey": args.nvd_api_key}
        total_processed = processed

        while ws <= end_dt:
            if we > end_dt:
                we = end_dt

            logging.info(
                "window start=%s end=%s startIndex=%d processed=%d",
                ws.isoformat(), we.isoformat(), start_index, total_processed,
            )

            params = {
                "pubStartDate": fmt_nvd_ts(ws),
                "pubEndDate": fmt_nvd_ts(we),
                "startIndex": start_index,
                "resultsPerPage": NVD_PAGE_SIZE,
            }
            url = NVD_API_BASE + "?" + urlencode(params)
            payload = fetch_json(url, headers=headers, timeout=90, retries=6)
            vulns = payload.get("vulnerabilities") or []
            total = int(payload.get("totalResults") or 0)

            batch: List[Tuple[Any, ...]] = []
            for v in vulns:
                cve = (v or {}).get("cve") or {}
                cve_id = (cve.get("id") or "").upper()
                year = year_from_cve(cve_id)
                if not cve_id or year is None:
                    continue

                metrics = cve.get("metrics") or {}
                v31_s, v31_v, v31_sev, v31_src = metric_value(metrics, "cvssMetricV31")
                v30_s, v30_v, v30_sev, v30_src = metric_value(metrics, "cvssMetricV30")
                v2_s, v2_v, v2_sev, v2_src = metric_value(metrics, "cvssMetricV2")

                best_score = v31_s if v31_s is not None else (v30_s if v30_s is not None else (v2_s or 0.0))
                best_vector = v31_v or v30_v or v2_v
                best_sev = v31_sev or v30_sev or v2_sev or ""
                best_source = "NIST" if (v31_src or v30_src) else (v2_src or cve.get("sourceIdentifier"))

                weaknesses = cve.get("weaknesses") or []
                refs = cve.get("references") or []
                configs = cve.get("configurations") or []
                vendor_comments = cve.get("vendorComments") or []

                products = []
                seen = set()
                for conf in configs:
                    for node in conf.get("nodes", []) or []:
                        for m in node.get("cpeMatch", []) or []:
                            if not m.get("vulnerable"):
                                continue
                            crit = m.get("criteria") or ""
                            parts = crit.split(":")
                            if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                                vp = f"{parts[3]}:{parts[4]}"
                                if vp not in seen:
                                    seen.add(vp)
                                    products.append(vp)

                epss_score, epss_pct = epss_map.get(cve_id, (None, None))

                published = cve.get("published")
                published_date = published[:10] if isinstance(published, str) and len(published) >= 10 else None
                last_mod = parse_iso_dt(cve["lastModified"]) if cve.get("lastModified") else None

                batch.append(
                    (
                        cve_id,
                        year,
                        best_score,
                        best_sev,
                        english_description(cve.get("descriptions") or []),
                        best_vector,
                        pick_primary_cwe(weaknesses),
                        bool(cve.get("cisaExploitAdd")),
                        best_source,
                        published_date,
                        cve.get("vulnStatus") or "",
                        epss_score,
                        json.dumps(products),
                        datetime.now(timezone.utc),
                        v31_s,
                        v31_v,
                        v31_sev,
                        v30_s,
                        v30_v,
                        v30_sev,
                        v2_s,
                        v2_v,
                        v2_sev,
                        json.dumps(refs),
                        json.dumps(configs),
                        json.dumps(weaknesses),
                        json.dumps(vendor_comments),
                        cve.get("sourceIdentifier"),
                        cve.get("vulnStatus"),
                        last_mod,
                        epss_pct,
                    )
                )

            with conn.cursor() as cur:
                upsert_batch(cur, batch)
                total_processed += len(batch)

                # Advance cursor/window
                if len(vulns) == 0 or start_index + len(vulns) >= total:
                    # move to next window
                    next_ws = we + timedelta(seconds=1)
                    next_we = min(end_dt, next_ws + timedelta(days=args.window_days) - timedelta(seconds=1))
                    save_checkpoint(cur, next_ws, next_we, 0, total_processed, status="running")
                    ws, we, start_index = next_ws, next_we, 0
                else:
                    start_index = start_index + len(vulns)
                    save_checkpoint(cur, ws, we, start_index, total_processed, status="running")

                conn.commit()

            logging.info(
                "progress window=%s..%s fetched=%d total_window=%d total_processed=%d",
                params["pubStartDate"], params["pubEndDate"], len(vulns), total, total_processed,
            )

            with conn.cursor() as cur:
                nvd_rows = rows_total(cur)
                err24 = failed_runs_last_24h(cur)
            emit_status(
                status_file=args.status_file,
                status="running",
                ws=ws,
                we=we,
                processed=total_processed,
                nvd_rows=nvd_rows,
                epss_loaded=epss_loaded,
                errors_last_24h=err24,
                end_dt=end_dt,
            )

            time.sleep(args.rate_sleep)

        with conn.cursor() as cur:
            save_checkpoint(cur, ws, we, start_index, total_processed, status="completed")
            cur.execute(
                "UPDATE nvd_backfill_runs SET status='completed', completed_at=NOW(), processed_cves=%s WHERE id=%s",
                (total_processed, run_id),
            )
            nvd_rows = rows_total(cur)
            err24 = failed_runs_last_24h(cur)
            conn.commit()
        emit_status(
            status_file=args.status_file,
            status="completed",
            ws=ws,
            we=we,
            processed=total_processed,
            nvd_rows=nvd_rows,
            epss_loaded=epss_loaded,
            errors_last_24h=err24,
            end_dt=end_dt,
        )

        logging.info("historical backfill completed; processed=%d", total_processed)
        return 0

    except Exception as e:
        logging.exception("historical backfill failed: %s", e)
        try:
            with conn.cursor() as cur:
                if run_id is not None:
                    cur.execute(
                        "UPDATE nvd_backfill_runs SET status='failed', completed_at=NOW(), note=%s WHERE id=%s",
                        (str(e)[:1000], run_id),
                    )
                cur.execute(
                    "UPDATE nvd_backfill_checkpoint SET status='failed', updated_at=NOW() WHERE id=1"
                )
                nvd_rows = rows_total(cur)
                err24 = failed_runs_last_24h(cur)
                conn.commit()
            emit_status(
                status_file=args.status_file,
                status="failed",
                ws=start_dt,
                we=end_dt,
                processed=0,
                nvd_rows=nvd_rows,
                epss_loaded=epss_loaded if 'epss_loaded' in locals() else 0,
                errors_last_24h=err24,
                end_dt=end_dt,
                error_message=str(e),
            )
        except Exception:
            pass
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
