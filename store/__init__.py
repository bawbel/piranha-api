"""
PiranhaDB — Store factory.

Picks the right store implementation based on environment variables.
Routers always import from here — never from concrete implementations.

Phase matrix:
    DATABASE_URL not set  →  file-based store (current)
    DATABASE_URL set      →  PostgreSQL store  (Phase 3)
    REDIS_URL set         →  Redis cache active in any phase
"""

import os

# Future PostgreSQL switch — uncomment when DATABASE_URL is set:
# if os.environ.get("DATABASE_URL"):
#     from store.postgres_records_store import *
#     from store.postgres_scan_store import *
# else:

from store.records_store import (  # noqa: F401
    get_all, get_one, reload, count,
    severity_from_cvss, to_summary,
)
from store.scan_store import (  # noqa: F401
    save_scan, get_latest, get_history,
    save_submission, get_submission,
)
from store.cache import cache_info, cache_flush  # noqa: F401
