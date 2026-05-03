"""
PiranhaDB — Cache layer.

Redis cache that is completely transparent when not configured.
When REDIS_URL is not set, all cache calls are no-ops — the app
works identically, just without caching.

When REDIS_URL is set (Phase 3):
    - GET /records            → cached 1 hour
    - GET /records/{ave_id}   → cached 1 hour
    - GET /stats/ecosystem    → cached 5 minutes
    - GET /registry-scan/*    → cached 10 minutes

Connection is lazy — Redis is not required at startup.
If Redis goes down mid-run, all cache calls silently bypass.

Usage:
    from store.cache import cache_get, cache_set, cache_delete, cache_flush

    data = cache_get("records:all")
    if data is None:
        data = _load_from_db()
        cache_set("records:all", data, ttl=3600)
"""

import json
import os
from typing import Optional

# ── TTL constants (seconds) ───────────────────────────────────────────────────

TTL_RECORDS     = int(os.environ.get("CACHE_TTL_RECORDS",     "3600"))   # 1 hour
TTL_SCAN        = int(os.environ.get("CACHE_TTL_SCAN",        "600"))    # 10 minutes
TTL_STATS       = int(os.environ.get("CACHE_TTL_STATS",       "300"))    # 5 minutes
TTL_SUBMISSION  = int(os.environ.get("CACHE_TTL_SUBMISSION",  "86400"))  # 24 hours

# ── Key helpers ───────────────────────────────────────────────────────────────

KEY_ALL_RECORDS   = "piranha:records:all"
KEY_RECORD        = lambda ave_id: f"piranha:record:{ave_id}"   # noqa: E731
KEY_SCAN_LATEST   = lambda source: f"piranha:scan:latest:{source}"  # noqa: E731
KEY_SCAN_HISTORY  = lambda source, n: f"piranha:scan:history:{source}:{n}"  # noqa: E731
KEY_STATS_ECO     = "piranha:stats:ecosystem"
KEY_SUBMISSION    = lambda sid: f"piranha:submit:{sid}"  # noqa: E731

# ── Connection ────────────────────────────────────────────────────────────────

_redis_client = None
_redis_failed  = False   # don't retry after a connection failure in the same process


def _get_redis():
    """Return Redis client if REDIS_URL is set and connection succeeds."""
    global _redis_client, _redis_failed
    if _redis_failed:
        return None
    if _redis_client is not None:
        return _redis_client

    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        return None

    try:
        import redis  # noqa: PLC0415
        _redis_client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            retry_on_timeout=False,
        )
        # Ping to verify connection
        _redis_client.ping()
        return _redis_client
    except Exception:  # noqa: BLE001
        _redis_failed = True
        _redis_client = None
        return None


# ── Public API ────────────────────────────────────────────────────────────────


def cache_get(key: str) -> Optional[dict]:
    """
    Get a value from cache.

    Returns:
        Parsed dict if cache hit, None if miss or Redis not available.
    """
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None


def cache_set(key: str, value: dict | list, ttl: int = TTL_RECORDS) -> None:
    """
    Set a value in cache with TTL.

    Silently does nothing if Redis is not available.
    """
    r = _get_redis()
    if r is None:
        return
    try:
        r.setex(key, ttl, json.dumps(value, ensure_ascii=False))
    except Exception:  # noqa: BLE001
        pass


def cache_delete(key: str) -> None:
    """Delete a cache key. Silently does nothing if Redis not available."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.delete(key)
    except Exception:  # noqa: BLE001
        pass


def cache_flush(pattern: str = "piranha:*") -> int:
    """
    Flush all PiranhaDB cache keys matching pattern.

    Returns:
        Number of keys deleted, or 0 if Redis not available.
    """
    r = _get_redis()
    if r is None:
        return 0
    try:
        keys = r.keys(pattern)
        if keys:
            return r.delete(*keys)
        return 0
    except Exception:  # noqa: BLE001
        return 0


def cache_info() -> dict:
    """Return cache status for /health endpoint."""
    r = _get_redis()
    if r is None:
        return {
            "enabled":  bool(os.environ.get("REDIS_URL")),
            "connected": False,
            "reason":   "REDIS_URL not set" if not os.environ.get("REDIS_URL") else "connection failed",
        }
    try:
        info = r.info("memory")
        return {
            "enabled":    True,
            "connected":  True,
            "used_memory": info.get("used_memory_human", "unknown"),
        }
    except Exception:  # noqa: BLE001
        return {"enabled": True, "connected": False, "reason": "ping failed"}
