"""
PiranhaDB — Configuration.

All environment variables and constants live here.
Never import os.environ directly in routers or store modules.

Phase 1 (current):  no DATABASE_URL, no REDIS_URL
Phase 2 (UI):       add PIRANHA_UI_URL to CORS whitelist
Phase 3 (scale):    add DATABASE_URL + REDIS_URL — zero code changes needed
"""

import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parent
RECORDS_DIR = Path(os.environ.get("PIRANHA_RECORDS_DIR", str(BASE_DIR / "records")))
SCANS_DIR   = Path(os.environ.get("PIRANHA_SCANS_DIR",   str(BASE_DIR / "scans")))

# ── Environment ───────────────────────────────────────────────────────────────

ENV      = os.environ.get("PIRANHA_ENV", "development")
IS_PROD  = ENV == "production"

# ── Database (Phase 3) ────────────────────────────────────────────────────────

DATABASE_URL = os.environ.get("DATABASE_URL", "")    # triggers PostgreSQL store
REDIS_URL    = os.environ.get("REDIS_URL",    "")    # triggers Redis cache

# ── GitHub ────────────────────────────────────────────────────────────────────

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
AVE_REPO     = os.environ.get("BAWBEL_AVE_REPO", "bawbel/bawbel-ave")
AVE_REPO_API = f"https://api.github.com/repos/{AVE_REPO}/contents/records"
AVE_RAW_BASE = f"https://raw.githubusercontent.com/{AVE_REPO}/main/records"

# ── Security ──────────────────────────────────────────────────────────────────

SCAN_RATE_LIMIT = int(os.environ.get("SCAN_RATE_LIMIT", "10"))   # req/min per IP
SCAN_MAX_BYTES  = int(os.environ.get("SCAN_MAX_BYTES", str(100 * 1024)))  # 100KB

# ── CORS ──────────────────────────────────────────────────────────────────────
# Phase 2: add PIRANHA_UI_URL=https://piranha.bawbel.io to Railway env vars
# The value is automatically added to allowed origins below.

_extra_origins = [
    o.strip() for o in os.environ.get("PIRANHA_UI_URL", "").split(",") if o.strip()
]
CORS_ORIGINS = ["*"] if not IS_PROD else [
    "https://bawbel.io",
    "https://api.piranha.bawbel.io",
    *_extra_origins,
]

# ── Cache TTLs (seconds) ──────────────────────────────────────────────────────

CACHE_TTL_RECORDS    = int(os.environ.get("CACHE_TTL_RECORDS",    "3600"))  # 1 hour
CACHE_TTL_SCAN       = int(os.environ.get("CACHE_TTL_SCAN",       "600"))   # 10 min
CACHE_TTL_STATS      = int(os.environ.get("CACHE_TTL_STATS",      "300"))   # 5 min
CACHE_TTL_SUBMISSION = int(os.environ.get("CACHE_TTL_SUBMISSION",  "86400"))  # 24 h

# ── History ───────────────────────────────────────────────────────────────────

MAX_SCAN_HISTORY = int(os.environ.get("MAX_SCAN_HISTORY", "52"))  # 1 year

# ── API ───────────────────────────────────────────────────────────────────────

API_VERSION = "1.1.0"
API_TITLE   = "PiranhaDB — Agentic AI Threat Intelligence"
API_DESC    = (
    "The Shodan of agentic AI. "
    "Real-time threat intelligence for MCP servers, skill files, and agent components. "
    "Free, open, no API key required. Apache 2.0."
)

# ── Ecosystem sources ─────────────────────────────────────────────────────────

GITHUB_SKILL_REPOS = [
    "google/skills",
    "microsoft/skills",
    "vercel/skills",
    "supabase/skills",
]

REGISTRIES = {
    "smithery":     "https://registry.smithery.ai",
    "mcp-registry": "https://registry.modelcontextprotocol.io",
}
