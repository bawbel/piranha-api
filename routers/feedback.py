"""
PiranhaDB - False-positive feedback router.

POST /feedback/false-positive

Receives anonymous false-positive signals from `bawbel accept --report`.
No file content is transmitted. Used to track suppression patterns across
the community and improve AVE detection rules.

Payload (from bawbel-scanner v1.2.0+):
    ave_id         : str  - AVE record ID e.g. AVE-2026-00011
    engine         : str  - detection engine: pattern | yara | semgrep
    confidence     : float - scanner confidence score at time of finding (0-1)
    context_hash   : str  - SHA-256 of match context (no file content)
    scanner_version: str  - bawbel-scanner version string
    justification  : str | None - optional free-text justification (max 500 chars)
"""

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

from config import SCANS_DIR

router = APIRouter(prefix="/feedback", tags=["Feedback"])

_lock = threading.Lock()
_FEEDBACK_DIR = SCANS_DIR / "feedback"
_MAX_JUSTIFICATION = 500
_VALID_ENGINES = {"pattern", "yara", "semgrep"}


# -- Models -------------------------------------------------------------------


class FalsePositiveReport(BaseModel):
    ave_id:          str   = Field(..., description="AVE record ID e.g. AVE-2026-00011")
    engine:          str   = Field(..., description="Detection engine: pattern | yara | semgrep")
    confidence:      float = Field(..., ge=0.0, le=1.0, description="Scanner confidence at time of finding")
    context_hash:    str   = Field(..., min_length=8, max_length=64, description="SHA-256 of match context")
    scanner_version: str   = Field(..., description="bawbel-scanner version string")
    justification:   Optional[str] = Field(None, max_length=_MAX_JUSTIFICATION)

    @field_validator("ave_id")
    @classmethod
    def validate_ave_id(cls, v: str) -> str:
        v = v.upper().strip()
        if not v.startswith("AVE-"):
            raise ValueError("ave_id must start with AVE-")
        return v

    @field_validator("engine")
    @classmethod
    def validate_engine(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in _VALID_ENGINES:
            raise ValueError(f"engine must be one of: {sorted(_VALID_ENGINES)}")
        return v

    @field_validator("context_hash")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        v = v.lower().strip()
        if not all(c in "0123456789abcdef" for c in v):
            raise ValueError("context_hash must be a hex string")
        return v


# -- Storage ------------------------------------------------------------------


def _write_feedback(data: dict) -> str:
    """Write feedback entry to disk. Returns entry ID."""
    _FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
    raw = f"{data['ave_id']}{data['context_hash']}{ts}"
    eid = hashlib.sha256(raw.encode()).hexdigest()[:12]
    data["entry_id"] = eid
    data["received_at"] = ts

    path = _FEEDBACK_DIR / f"{ts.replace(':', '-')}_{eid}.json"
    tmp  = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:  # nosec B108
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return eid


def _count_feedback() -> dict:
    """Return per-AVE false-positive counts."""
    if not _FEEDBACK_DIR.exists():
        return {}
    counts: dict[str, int] = {}
    for fp in _FEEDBACK_DIR.glob("*.json"):
        try:
            with open(fp, encoding="utf-8") as fh:
                entry = json.load(fh)
            ave = entry.get("ave_id", "")
            counts[ave] = counts.get(ave, 0) + 1
        except Exception:  # noqa: BLE001
            pass
    return counts


# -- Routes -------------------------------------------------------------------


@router.post("/false-positive")
def report_false_positive(body: FalsePositiveReport):
    """
    Submit an anonymous false-positive signal.

    Called by `bawbel accept --report` after the user suppresses a finding.
    No file content is transmitted. The context_hash is a one-way hash of
    the match context and cannot be used to reconstruct the original content.

    Rate limiting is handled at the Railway edge. Each report is stored
    anonymously and used to refine AVE detection rules.
    """
    with _lock:
        eid = _write_feedback({
            "ave_id":          body.ave_id,
            "engine":          body.engine,
            "confidence":      body.confidence,
            "context_hash":    body.context_hash,
            "scanner_version": body.scanner_version,
            "justification":   body.justification,
        })

    return {
        "status":          "accepted",
        "entry_id":        eid,
        "ave_id":          body.ave_id,
        "message":         "False-positive signal recorded. Thank you.",
    }


@router.get("/stats")
def feedback_stats():
    """
    Aggregate false-positive counts per AVE record.

    Used by the bawbel/ave maintainers to identify rules with high
    false-positive rates and prioritise rule refinement.
    """
    counts = _count_feedback()
    total  = sum(counts.values())
    return {
        "total_reports":    total,
        "by_ave_id":        dict(sorted(counts.items(), key=lambda x: -x[1])),
        "generated_at":     datetime.now(timezone.utc).isoformat(),
    }
