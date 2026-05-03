"""
PiranhaDB — Agentic AI Threat Intelligence API

The Shodan of agentic AI. Real-time threat intelligence for MCP servers,
skill files, and agent components. Free, open, no API key required.

Endpoints:
    GET  /                              → API info
    GET  /health                        → health check
    GET  /records                       → list AVE records
    GET  /records/{ave_id}              → full AVE record
    GET  /records/{ave_id}/detection    → detection guidance
    GET  /records/search?q=...          → search records
    GET  /registry-scan/latest          → latest registry scan
    GET  /registry-scan/history         → weekly trend data
    GET  /registry-scan/sources         → available sources
    GET  /github-scan/{owner}/{repo}    → latest GitHub skills scan
    GET  /github-scan/sources           → scanned skill repos
    GET  /stats                         → basic stats (v0.1 compat)
    GET  /stats/ecosystem               → full ecosystem stats
    POST /scan                          → on-demand scan (URL or content)
    GET  /scan/{submission_id}          → get scan result

Deploy:
    Railway: uvicorn main:app --host 0.0.0.0 --port $PORT
    Local:   uvicorn main:app --reload
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from config import API_VERSION, API_TITLE, API_DESC, CORS_ORIGINS
import store.records_store as records_store

# ── Routers ───────────────────────────────────────────────────────────────────
from routers.records      import router as records_router
from routers.registry_scan import router as registry_scan_router
from routers.github_scan  import router as github_scan_router
from routers.stats        import router as stats_router
from routers.submit       import router as submit_router


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-load records cache on startup."""
    count = records_store.reload()
    print(f"PiranhaDB started — {count} AVE records loaded")
    yield
    print("PiranhaDB shutting down")


# ── App ───────────────────────────────────────────────────────────────────────


app = FastAPI(
    title       = API_TITLE,
    description = API_DESC,
    version     = API_VERSION,
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = CORS_ORIGINS,
    allow_methods  = ["GET", "POST"],
    allow_headers  = ["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(records_router)
app.include_router(registry_scan_router)
app.include_router(github_scan_router)
app.include_router(stats_router)
app.include_router(submit_router)


# ── Root ──────────────────────────────────────────────────────────────────────


@app.get("/", include_in_schema=False)
def root():
    return {
        "name":        "PiranhaDB",
        "tagline":     "The Shodan of agentic AI",
        "version":     API_VERSION,
        "description": API_DESC,
        "records":     records_store.count(),
        "license":     "Apache 2.0",
        "free":        True,
        "auth":        None,
        "endpoints": {
            "ave_records":     "GET /records",
            "record_detail":   "GET /records/{ave_id}",
            "search":          "GET /records/search?q={query}",
            "registry_scan":   "GET /registry-scan/latest",
            "github_scan":     "GET /github-scan/{owner}/{repo}",
            "ecosystem_stats": "GET /stats/ecosystem",
            "on_demand_scan":  "POST /scan",
        },
        "links": {
            "docs":         "https://bawbel.io/docs",
            "scanner":      "https://github.com/bawbel/bawbel-scanner",
            "ave_standard": "https://github.com/bawbel/bawbel-ave",
            "bawbel_io":    "https://bawbel.io",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health():
    from store.cache import cache_info
    return {
        "status":    "ok",
        "records":   records_store.count(),
        "version":   API_VERSION,
        "cache":     cache_info(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Legacy endpoint aliases (v0.1 backwards compat) ──────────────────────────


@app.get("/ave", include_in_schema=False)
def legacy_list():
    """v0.1 compat — redirects to /records."""
    from routers.records import list_records
    return list_records()


@app.get("/ave/{ave_id}", include_in_schema=False)
def legacy_get(ave_id: str):
    """v0.1 compat — redirects to /records/{ave_id}."""
    from routers.records import get_record
    return get_record(ave_id)
