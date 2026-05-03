"""
PiranhaDB — AVE records store (file-based implementation).

Loads AVE records from the local records/ directory (synced from bawbel-ave).
Wraps access with Redis cache when REDIS_URL is set.

Upgrade to PostgreSQL:
    1. Create store/postgres_records_store.py implementing RecordsStoreProtocol
    2. store/__init__.py picks it up automatically when DATABASE_URL is set
    3. This file becomes the fallback for environments without a database
"""

import json
import threading
import time
from typing import Optional

from config import RECORDS_DIR, IS_PROD
from store.owasp_mcp_map import get_owasp_mcp
from store.cache import (
    cache_get, cache_set, cache_delete,
    KEY_ALL_RECORDS, KEY_RECORD, TTL_RECORDS,
)

_lock:      threading.Lock  = threading.Lock()
_disk_cache: dict[str, dict] = {}
_loaded:    bool            = False
_loaded_at: float           = 0.0
_DISK_TTL = 3600


def _load_from_disk() -> dict[str, dict]:
    records: dict[str, dict] = {}
    if not RECORDS_DIR.exists():
        return records
    for path in sorted(RECORDS_DIR.glob("AVE-*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                record = json.load(f)
            ave_id = record.get("ave_id", path.stem)
            records[ave_id] = record
        except Exception:  # noqa: BLE001
            pass
    return records


def _ensure_loaded() -> None:
    global _loaded, _loaded_at, _disk_cache
    now = time.monotonic()
    if _loaded and IS_PROD and (now - _loaded_at) < _DISK_TTL:
        return
    with _lock:
        if _loaded and IS_PROD and (now - _loaded_at) < _DISK_TTL:
            return
        _disk_cache = _load_from_disk()
        _loaded     = True
        _loaded_at  = now


def get_all() -> dict[str, dict]:
    """Return all records. Uses Redis cache when available."""
    cached = cache_get(KEY_ALL_RECORDS)
    if cached is not None:
        return cached
    _ensure_loaded()
    cache_set(KEY_ALL_RECORDS, _disk_cache, ttl=TTL_RECORDS)
    return _disk_cache


def get_one(ave_id: str) -> Optional[dict]:
    """Return a single record. Uses Redis cache when available."""
    key_upper = ave_id.upper()
    cached    = cache_get(KEY_RECORD(key_upper))
    if cached is not None:
        return cached
    _ensure_loaded()
    record = _disk_cache.get(ave_id) or _disk_cache.get(key_upper)
    if record:
        cache_set(KEY_RECORD(key_upper), record, ttl=TTL_RECORDS)
    return record


def reload() -> int:
    """Force reload from disk, bust Redis cache. Returns count loaded."""
    global _loaded, _loaded_at, _disk_cache
    with _lock:
        _disk_cache = _load_from_disk()
        _loaded     = True
        _loaded_at  = time.monotonic()
    cache_delete(KEY_ALL_RECORDS)
    return len(_disk_cache)


def count() -> int:
    _ensure_loaded()
    return len(_disk_cache)


def severity_from_cvss(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def to_summary(record: dict) -> dict:
    ave_id = record.get("ave_id", "")
    return {
        "ave_id":         ave_id,
        "title":          record.get("title"),
        "attack_class":   record.get("attack_class"),
        "severity":       severity_from_cvss(record.get("cvss_ai_score", 0)),
        "cvss_ai_score":  record.get("cvss_ai_score"),
        "component_type": record.get("component_type"),
        "status":         record.get("status", "active"),
        "mutation_count": record.get("mutation_count", 0),
        "published":      record.get("published"),
        "owasp_mapping":  record.get("owasp_mapping", []),
        "owasp_mcp":      get_owasp_mcp(ave_id),
        "piranha_url":    f"https://api.piranha.bawbel.io/records/{ave_id}",
    }
