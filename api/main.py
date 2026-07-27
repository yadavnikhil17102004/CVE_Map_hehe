import json
import os
from collections import defaultdict
from contextlib import contextmanager
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

APP_TITLE = "CVE-Intel API"
APP_VERSION = "0.1.0"

DB_NAME = os.getenv("POSTGRES_DB", "cveintel")
DB_HOST = os.getenv("POSTGRES_HOST", "postgres")
DB_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
DB_USER = os.getenv("POSTGRES_API_USER") or os.getenv("POSTGRES_USER", "cveintel")
DB_PASSWORD = os.getenv("POSTGRES_API_PASSWORD") or os.getenv("POSTGRES_PASSWORD", "")
DB_SSLMODE = os.getenv("POSTGRES_SSLMODE", "disable")

if not DB_PASSWORD:
    raise RuntimeError("Database password not configured for API user")


limiter = Limiter(key_func=get_remote_address, default_limits=["240/minute"])
app = FastAPI(title=APP_TITLE, version=APP_VERSION)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(GZipMiddleware, minimum_size=1024)


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    return value


def make_json_response(payload: Any) -> JSONResponse:
    return JSONResponse(content=json.loads(json.dumps(payload, default=_json_default)))


@contextmanager
def db_cursor():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
        sslmode=DB_SSLMODE,
    )
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
    finally:
        conn.close()


def row_to_repo(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["repo_id"],
        "name": row.get("repo_name"),
        "full_name": row.get("full_name"),
        "html_url": row.get("repo_url"),
        "description": row.get("description"),
        "stargazers_count": row.get("stargazers_count") or 0,
        "forks_count": row.get("forks_count") or 0,
        "language": row.get("language"),
        "updated_at": row.get("updated_at"),
        "pushed_at": row.get("pushed_at"),
        "created_at": row.get("created_at"),
        "topics": row.get("topics") or [],
        "owner": {
            "login": row.get("owner_login"),
            "html_url": row.get("owner_html_url"),
        },
        "clone_url": row.get("clone_url"),
        "has_code": row.get("has_code"),
        "age_days": row.get("age_days"),
    }


def row_to_compact_intel(row: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    mapping = {
        "s": "cvss_score",
        "v": "severity",
        "d": "description",
        "c": "cvss_vector",
        "w": "cwe",
        "r": "source",
        "p": "published_date",
        "u": "status",
        "e": "epss_score",
    }
    for k, col in mapping.items():
        val = row.get(col)
        if val is not None and val != "":
            out[k] = val

    if row.get("kev_flag"):
        out["k"] = True

    products = row.get("products")
    if products:
        out["q"] = products

    return out


@app.get("/api/health")
@limiter.limit("60/minute")
def health(request: Request):
    with db_cursor() as cur:
        cur.execute("SELECT 1")
        cur.fetchone()
    return {"ok": True, "service": "cve-intel-api"}


@app.get("/api/cve/{year}")
@limiter.limit("90/minute")
def get_cve_by_year(request: Request, year: int):
    if year < 1999 or year > 2100:
        raise HTTPException(status_code=400, detail="invalid year")

    with db_cursor() as cur:
        cur.execute(
            """
            SELECT cve_id, repo_id, repo_name, full_name, repo_url, description,
                   stargazers_count, forks_count, language, updated_at, pushed_at,
                   created_at, topics, owner_login, owner_html_url, clone_url,
                   has_code, age_days
            FROM cve_repos
            WHERE year = %s
            ORDER BY cve_id ASC, stargazers_count DESC NULLS LAST, repo_id ASC
            """,
            (year,),
        )
        rows = cur.fetchall()

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["cve_id"]].append(row_to_repo(row))

    payload = {
        "year": year,
        "cves": [
            {"cve_id": cve_id, "repositories": repos}
            for cve_id, repos in grouped.items()
        ],
    }
    return make_json_response(payload)


@app.get("/api/intel/{year}")
@limiter.limit("90/minute")
def get_intel_by_year(request: Request, year: int):
    if year < 1999 or year > 2100:
        raise HTTPException(status_code=400, detail="invalid year")

    with db_cursor() as cur:
        cur.execute(
            """
            SELECT cve_id, cvss_score, severity, description, cvss_vector,
                   cwe, kev_flag, source, published_date, status,
                   epss_score, products
            FROM nvd_intel
            WHERE year = %s
            ORDER BY cve_id ASC
            """,
            (year,),
        )
        rows = cur.fetchall()

    payload = {row["cve_id"]: row_to_compact_intel(row) for row in rows}
    return make_json_response(payload)


@app.get("/api/news")
@limiter.limit("120/minute")
def get_news(request: Request, limit: int = Query(200, ge=1, le=500)):
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT title, link, description, source, tier, image_url,
                   pub_date_raw, COALESCE(last_updated, MAX(ingested_at) OVER ()) AS top_updated
            FROM news_items
            ORDER BY published_at DESC NULLS LAST, id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()

    last_updated = None
    articles: List[Dict[str, Any]] = []
    for row in rows:
        if row.get("top_updated") and not last_updated:
            last_updated = row["top_updated"]
        articles.append(
            {
                "title": row.get("title"),
                "link": row.get("link"),
                "description": row.get("description"),
                "pub_date": row.get("pub_date_raw"),
                "source": row.get("source"),
                "tier": row.get("tier"),
                "image_url": row.get("image_url"),
            }
        )

    payload = {
        "last_updated": last_updated,
        "articles": articles,
    }
    return make_json_response(payload)


@app.get("/api/search")
@limiter.limit("120/minute")
def search(
    request: Request,
    q: str = Query(..., min_length=2, max_length=200),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    year: Optional[int] = Query(None, ge=1999, le=2100),
    severity: Optional[str] = Query(None),
    kev: Optional[bool] = Query(None),
):
    query = q.strip()
    if not query:
        raise HTTPException(status_code=400, detail="empty query")

    severity_norm = severity.strip().upper() if severity else None
    severity_allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if severity_norm and severity_norm not in severity_allowed:
        raise HTTPException(status_code=400, detail="severity must be one of LOW, MEDIUM, HIGH, CRITICAL")

    like = f"%{query.lower()}%"
    offset = (page - 1) * per_page

    text_match_clauses = [
        "LOWER(c.cve_id) LIKE %(like)s",
        "LOWER(COALESCE(c.repo_name, '')) LIKE %(like)s",
        "LOWER(COALESCE(c.full_name, '')) LIKE %(like)s",
        "LOWER(COALESCE(c.description, '')) LIKE %(like)s",
        "LOWER(COALESCE(c.language, '')) LIKE %(like)s",
        "LOWER(COALESCE(c.owner_login, '')) LIKE %(like)s",
        "LOWER(COALESCE(c.topics::text, '')) LIKE %(like)s",
        "LOWER(COALESCE(n.description, '')) LIKE %(like)s",
        "LOWER(COALESCE(n.cwe, '')) LIKE %(like)s",
        "LOWER(COALESCE(n.cvss_vector, '')) LIKE %(like)s",
    ]

    params: Dict[str, Any] = {
        "like": like,
        "limit": per_page,
        "offset": offset,
    }

    filters = ["(" + " OR ".join(text_match_clauses) + ")"]
    if year is not None:
        filters.append("c.year = %(year)s")
        params["year"] = year
    if severity_norm:
        filters.append("n.severity = %(severity)s")
        params["severity"] = severity_norm
    if kev is not None:
        filters.append("COALESCE(n.kev_flag, false) = %(kev)s")
        params["kev"] = kev

    filter_sql = " AND ".join(filters)

    with db_cursor() as cur:
        cur.execute(
            f"""
            WITH matched AS (
              SELECT DISTINCT c.cve_id, c.year
              FROM cve_repos c
              LEFT JOIN nvd_intel n ON n.cve_id = c.cve_id
              WHERE {filter_sql}
            )
            SELECT COUNT(*)::BIGINT AS total FROM matched
            """,
            params,
        )
        total = int(cur.fetchone()["total"])

        cur.execute(
            f"""
            WITH matched AS (
              SELECT DISTINCT c.cve_id, c.year
              FROM cve_repos c
              LEFT JOIN nvd_intel n ON n.cve_id = c.cve_id
              WHERE {filter_sql}
            )
            SELECT cve_id, year
            FROM matched
            ORDER BY year DESC, cve_id DESC
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            params,
        )
        page_rows = cur.fetchall()

        cve_ids = [r["cve_id"] for r in page_rows]
        if not cve_ids:
            return {
                "query": query,
                "page": page,
                "per_page": per_page,
                "total": total,
                "cves": [],
            }

        cur.execute(
            """
            SELECT cve_id, repo_id, repo_name, full_name, repo_url, description,
                   stargazers_count, forks_count, language, updated_at, pushed_at,
                   created_at, topics, owner_login, owner_html_url, clone_url,
                   has_code, age_days
            FROM cve_repos
            WHERE cve_id = ANY(%s)
            ORDER BY cve_id ASC, stargazers_count DESC NULLS LAST, repo_id ASC
            """,
            (cve_ids,),
        )
        repo_rows = cur.fetchall()

        cur.execute(
            """
            SELECT cve_id, cvss_score, severity, description, cvss_vector,
                   cwe, kev_flag, source, published_date, status,
                   epss_score, products
            FROM nvd_intel
            WHERE cve_id = ANY(%s)
            """,
            (cve_ids,),
        )
        intel_rows = cur.fetchall()

    repos_by_cve: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in repo_rows:
        repos_by_cve[row["cve_id"]].append(row_to_repo(row))

    intel_by_cve = {row["cve_id"]: row_to_compact_intel(row) for row in intel_rows}
    year_by_cve = {row["cve_id"]: row["year"] for row in page_rows}

    ordered = []
    for row in page_rows:
        cve_id = row["cve_id"]
        item = {
            "year": year_by_cve[cve_id],
            "cve_id": cve_id,
            "repositories": repos_by_cve.get(cve_id, []),
        }
        intel = intel_by_cve.get(cve_id)
        if intel:
            item["intel"] = intel
        ordered.append(item)

    payload = {
        "query": query,
        "page": page,
        "per_page": per_page,
        "total": total,
        "cves": ordered,
    }
    return make_json_response(payload)
