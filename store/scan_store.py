"""
PiranhaDB — Scan results store.

Persists scan results as JSON files on disk (Railway volume or local).
Each source (smithery, mcp-registry, github/google/skills) gets its own
subdirectory with timestamped result files.

Layout:
    scans/
        smithery/
            2026-05-01T12:00:00.json
            2026-04-24T12:00:00.json
            ...
        mcp-registry/
            2026-05-01T12:00:00.json
            ...
        github-google-skills/
            2026-05-01T12:00:00.json
            ...
        submissions/
            2026-05-01T12:34:56_abc123.json
            ...

Design:
    - File-based, no database — deploys on Railway free tier
    - Atomic writes via temp file + rename
    - History capped at MAX_SCAN_HISTORY files per source
    - Thread-safe for concurrent Railway dyno reads
"""

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import SCANS_DIR, MAX_SCAN_HISTORY

_lock = threading.Lock()


# ── Path helpers ──────────────────────────────────────────────────────────────


def _source_dir(source: str) -> Path:
    """Return the directory for a scan source, creating it if needed."""
    # Sanitise source name — only allow safe characters for directory names
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in source)
    path = SCANS_DIR / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


# ── Atomic write ──────────────────────────────────────────────────────────────


def _write_atomic(path: Path, data: dict) -> None:
    """Write JSON atomically via temp file + rename."""
    dir_ = path.parent
    fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(Exception):
            os.unlink(tmp)
        raise


# ── History management ────────────────────────────────────────────────────────


def _prune_history(source_dir: Path) -> None:
    """Remove oldest scan files if over MAX_SCAN_HISTORY."""
    files = sorted(source_dir.glob("*.json"))
    while len(files) > MAX_SCAN_HISTORY:
        files[0].unlink(missing_ok=True)
        files = files[1:]


# ── Public API ────────────────────────────────────────────────────────────────


def save_scan(source: str, data: dict) -> Path:
    """
    Save a scan result for a source.

    Args:
        source: Source identifier e.g. "smithery", "mcp-registry",
                "github-google-skills"
        data:   The scan result dict

    Returns:
        Path of the saved file.
    """
    with _lock:
        dir_  = _source_dir(source)
        fname = f"{_timestamp()}.json"
        path  = dir_ / fname

        # Inject metadata
        data = {
            "scan_source":  source,
            "scan_date":    _timestamp(),
            **data,
        }

        _write_atomic(path, data)
        _prune_history(dir_)
        return path


def get_latest(source: str) -> Optional[dict]:
    """Return the most recent scan result for a source. None if none exist."""
    dir_  = _source_dir(source)
    files = sorted(dir_.glob("*.json"), reverse=True)
    if not files:
        return None
    try:
        with open(files[0], encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


def get_history(source: str, limit: int = 12) -> list[dict]:
    """
    Return scan history for a source, newest first.

    Args:
        source: Source identifier
        limit:  Max number of results to return

    Returns:
        List of scan result dicts, newest first.
    """
    dir_   = _source_dir(source)
    files  = sorted(dir_.glob("*.json"), reverse=True)[:limit]
    results: list[dict] = []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                results.append(json.load(fh))
        except Exception:  # noqa: BLE001
            pass
    return results


def save_submission(content: str, result: dict) -> str:
    """
    Save a user-submitted scan result.

    Returns:
        Submission ID (short hash of content + timestamp).
    """
    import hashlib
    ts    = _timestamp()
    sid   = hashlib.sha256(f"{content}{ts}".encode()).hexdigest()[:12]
    data  = {"submission_id": sid, "submitted_at": ts, **result}

    with _lock:
        dir_  = _source_dir("submissions")
        fname = f"{ts.replace(':', '-')}_{sid}.json"
        _write_atomic(dir_ / fname, data)

    return sid


def get_submission(sid: str) -> Optional[dict]:
    """Return a submission result by ID. None if not found."""
    dir_ = _source_dir("submissions")
    for f in dir_.glob(f"*_{sid}.json"):
        try:
            with open(f, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:  # noqa: BLE001
            pass
    return None


# ── Fix missing import ────────────────────────────────────────────────────────
import contextlib  # noqa: E402 (after function defs to avoid circular)
