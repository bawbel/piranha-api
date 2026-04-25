"""
PiranhaDB — AVE Record API  v1.0.0

Behavioral threat intelligence database for agentic AI vulnerabilities.
Serves AVE records from the bawbel-ave standard.

Endpoints:
  GET /                          → API info
  GET /ave                       → list all records (summary)
  GET /ave/{ave_id}              → full record
  GET /ave/{ave_id}/detection    → detection guidance only
  GET /search?q=<query>          → search across title, description, attack_class
  GET /stats                     → registry statistics
  GET /health                    → health check
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "PiranhaDB — AVE Record API",
    description = "Behavioral threat intelligence database for agentic AI vulnerabilities.",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["GET", "POST"],
    allow_headers  = ["*"],
)

# ── Record loader ─────────────────────────────────────────────────────────────

RECORDS_DIR = Path(os.environ.get("PIRANHA_RECORDS_DIR", "./records"))


def _load_records() -> dict[str, dict]:
    """Load all AVE-*.json files from RECORDS_DIR into memory."""
    records = {}
    if not RECORDS_DIR.exists():
        return records
    for path in sorted(RECORDS_DIR.glob("AVE-*.json")):
        try:
            with open(path) as f:
                record = json.load(f)
            ave_id = record.get("ave_id", path.stem)
            records[ave_id] = record
        except Exception:
            pass
    return records


# Load once at startup — start.sh runs sync_records.py first,
# so this always picks up the latest records from bawbel-ave.
_CACHE: dict[str, dict] = _load_records()


def _get_records() -> dict[str, dict]:
    return _CACHE


# ── Scanner rule mapping (all 40 AVE IDs) ────────────────────────────────────

_SCANNER_RULES: dict[str, str] = {
    "AVE-2026-00001": "bawbel-external-fetch",
    "AVE-2026-00002": "bawbel-mcp-tool-poisoning",
    "AVE-2026-00003": "bawbel-env-exfiltration",
    "AVE-2026-00004": "bawbel-shell-pipe",
    "AVE-2026-00005": "bawbel-destructive-command",
    "AVE-2026-00006": "bawbel-crypto-drain",
    "AVE-2026-00007": "bawbel-goal-override",
    "AVE-2026-00008": "bawbel-persistence-attempt",
    "AVE-2026-00009": "bawbel-jailbreak-instruction",
    "AVE-2026-00010": "bawbel-hidden-instruction",
    "AVE-2026-00011": "bawbel-dynamic-tool-call",
    "AVE-2026-00012": "bawbel-permission-escalation",
    "AVE-2026-00013": "bawbel-pii-exfiltration",
    "AVE-2026-00014": "bawbel-trust-escalation",
    "AVE-2026-00015": "bawbel-system-prompt-leak",
    "AVE-2026-00016": "bawbel-rag-injection",
    "AVE-2026-00017": "bawbel-mcp-impersonation",
    "AVE-2026-00018": "bawbel-tool-result-manipulation",
    "AVE-2026-00019": "bawbel-memory-poisoning",
    "AVE-2026-00020": "bawbel-a2a-injection",
    "AVE-2026-00021": "bawbel-autonomous-action",
    "AVE-2026-00022": "bawbel-scope-creep",
    "AVE-2026-00023": "bawbel-context-manipulation",
    "AVE-2026-00024": "bawbel-content-type-mismatch",  # Magika engine
    "AVE-2026-00025": "bawbel-history-injection",
    "AVE-2026-00026": "bawbel-tool-output-exfil",
    "AVE-2026-00027": "bawbel-multiturn-attack",
    "AVE-2026-00028": "bawbel-file-prompt-injection",
    "AVE-2026-00029": "bawbel-homoglyph-attack",       # YARA engine
    "AVE-2026-00030": "bawbel-role-claim-escalation",
    "AVE-2026-00031": "bawbel-feedback-poisoning",
    "AVE-2026-00032": "bawbel-network-recon",
    "AVE-2026-00033": "bawbel-unsafe-deserialization",
    "AVE-2026-00034": "bawbel-supply-chain-skill",
    "AVE-2026-00035": "bawbel-env-manipulation",       # YARA engine
    "AVE-2026-00036": "bawbel-lateral-movement",
    "AVE-2026-00037": "bawbel-vision-prompt-injection",
    "AVE-2026-00038": "bawbel-excessive-agency",
    "AVE-2026-00039": "bawbel-covert-channel",
    "AVE-2026-00040": "bawbel-unsafe-output",
}


def _scanner_rule(r: dict) -> Optional[str]:
    return _SCANNER_RULES.get(r.get("ave_id", ""))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity_from_cvss(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def _to_summary(r: dict) -> dict:
    return {
        "ave_id":              r.get("ave_id"),
        "title":               r.get("title"),
        "attack_class":        r.get("attack_class"),
        "severity":            _severity_from_cvss(r.get("cvss_ai_score", 0)),
        "cvss_ai_score":       r.get("cvss_ai_score"),
        "component_type":      r.get("component_type"),
        "status":              r.get("status", "active"),
        "mutation_count":      r.get("mutation_count", 0),
        "published":           r.get("published"),
        "owasp_mapping":       r.get("owasp_mapping", []),
        "bawbel_scanner_rule": _scanner_rule(r),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root():
    records = _get_records()
    return {
        "name":        "PiranhaDB",
        "description": "Behavioral threat intelligence database for agentic AI vulnerabilities",
        "version":     "1.0.0",
        "records":     len(records),
        "standard":    "AVE v0.1.0",
        "scanner":     "pip install bawbel-scanner",
        "docs":        "/docs",
        "endpoints": {
            "list":   "GET /ave",
            "get":    "GET /ave/{ave_id}",
            "search": "GET /search?q={query}",
            "stats":  "GET /stats",
        },
        "links": {
            "ave_standard":   "https://github.com/bawbel/bawbel-ave",
            "bawbel_scanner": "https://github.com/bawbel/bawbel-scanner",
            "pypi":           "https://pypi.org/project/bawbel-scanner/",
            "bawbel_io":      "https://bawbel.io",
        },
    }


@app.get("/health")
def health():
    records = _get_records()
    return {
        "status":    "ok",
        "records":   len(records),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/ave")
def list_records(
    severity:       Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    attack_class:   Optional[str] = Query(None, description="Filter by attack class substring"),
    component_type: Optional[str] = Query(None, description="skill, mcp, prompt, plugin"),
    status:         Optional[str] = Query(None, description="active, deprecated"),
    limit:          int           = Query(50, ge=1, le=200),
    offset:         int           = Query(0, ge=0),
):
    """List all AVE records with optional filtering."""
    records = _get_records()
    items   = [_to_summary(r) for r in records.values()]

    if severity:
        items = [i for i in items if i["severity"] == severity.upper()]
    if attack_class:
        items = [i for i in items if attack_class.lower() in (i["attack_class"] or "").lower()]
    if component_type:
        items = [i for i in items if i["component_type"] == component_type.lower()]
    if status:
        items = [i for i in items if i["status"] == status.lower()]

    total = len(items)
    return {"total": total, "offset": offset, "limit": limit,
            "records": items[offset: offset + limit]}


@app.get("/ave/{ave_id}")
def get_record(ave_id: str):
    """Get a single AVE record by ID."""
    records = _get_records()
    record  = records.get(ave_id) or records.get(ave_id.upper())
    if not record:
        raise HTTPException(
            status_code=404,
            detail={
                "error":   f"AVE record not found: {ave_id}",
                "hint":    "Browse all records at /ave",
                "scanner": "pip install bawbel-scanner",
            },
        )
    record = dict(record)
    record["bawbel_scanner_rule"] = _scanner_rule(record)
    return record


@app.get("/ave/{ave_id}/detection")
def get_detection(ave_id: str):
    """Get detection guidance for a specific AVE record."""
    records = _get_records()
    record  = records.get(ave_id) or records.get(ave_id.upper())
    if not record:
        raise HTTPException(status_code=404, detail=f"AVE record not found: {ave_id}")
    rule = _scanner_rule(record)
    return {
        "ave_id":                   record.get("ave_id"),
        "title":                    record.get("title"),
        "behavioral_fingerprint":   record.get("behavioral_fingerprint"),
        "detection_methodology":    record.get("detection_methodology"),
        "indicators_of_compromise": record.get("indicators_of_compromise", []),
        "bawbel_scanner_rule":      rule,
        "scan_command":             f"bawbel scan ./skill.md  # detects {rule or 'this pattern'}",
    }


@app.get("/search")
def search(
    q:     str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(20, ge=1, le=100),
):
    """Search AVE records by title, description, attack class, and behavioral fingerprint."""
    records = _get_records()
    query   = q.lower()
    results = []

    for r in records.values():
        score = 0
        if query in (r.get("ave_id") or "").lower():                score += 10
        if query in (r.get("title") or "").lower():                  score += 5
        if query in (r.get("attack_class") or "").lower():           score += 4
        if query in (r.get("description") or "").lower():            score += 2
        if query in (r.get("behavioral_fingerprint") or "").lower(): score += 1
        if any(query in (m or "").lower() for m in r.get("owasp_mapping", [])): score += 3
        if score > 0:
            s           = _to_summary(r)
            s["_score"] = score
            results.append(s)

    results.sort(key=lambda x: x["_score"], reverse=True)
    for r in results:
        del r["_score"]

    return {"query": q, "total": len(results), "records": results[:limit]}


@app.get("/stats")
def stats():
    """Registry statistics."""
    records         = _get_records()
    items           = list(records.values())
    by_severity     = {}
    by_type         = {}
    by_class        = {}
    total_mutations = 0

    for r in items:
        sev = _severity_from_cvss(r.get("cvss_ai_score", 0))
        by_severity[sev] = by_severity.get(sev, 0) + 1

        ct = r.get("component_type", "unknown")
        by_type[ct] = by_type.get(ct, 0) + 1

        ac = r.get("attack_class", "unknown")
        by_class[ac] = by_class.get(ac, 0) + 1

        total_mutations += r.get("mutation_count", 0)

    return {
        "total_records":     len(items),
        "total_mutations":   total_mutations,
        "by_severity":       by_severity,
        "by_component_type": by_type,
        "by_attack_class":   by_class,
        "schema_version":    "0.1.0",
        "last_updated":      datetime.now(timezone.utc).isoformat(),
    }


# ── Admin: hot-reload records without restart ─────────────────────────────────

@app.post("/reload", include_in_schema=False)
def reload_records():
    """
    Reload the in-memory cache from disk after a manual sync:
        python sync_records.py && curl -X POST http://localhost:8000/reload
    """
    global _CACHE
    _CACHE = _load_records()
    return {
        "status":    "reloaded",
        "records":   len(_CACHE),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }