"""
PiranhaDB — AVE records router.

GET /records                    — list all records with filtering
GET /records/{ave_id}           — full record
GET /records/{ave_id}/detection — detection guidance only
GET /search?q=...               — full-text search
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from store.records_store import get_all, get_one, to_summary, severity_from_cvss
from store.owasp_mcp_map import get_owasp_mcp

router = APIRouter(prefix="/records", tags=["AVE Records"])


@router.get("")
def list_records(
    severity:       Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    attack_class:   Optional[str] = Query(None, description="Filter by attack class substring"),
    component_type: Optional[str] = Query(None, description="skill | mcp | prompt | plugin"),
    status:         Optional[str] = Query(None, description="active | deprecated"),
    owasp_mcp:      Optional[str] = Query(None, description="Filter by OWASP MCP category e.g. MCP03"),
    limit:          int           = Query(50, ge=1, le=200),
    offset:         int           = Query(0, ge=0),
):
    """List AVE records with optional filtering."""
    records = get_all()
    items   = [to_summary(r) for r in records.values()]

    if severity:
        items = [i for i in items if i["severity"] == severity.upper()]
    if attack_class:
        items = [i for i in items if attack_class.lower() in (i.get("attack_class") or "").lower()]
    if component_type:
        items = [i for i in items if i.get("component_type") == component_type.lower()]
    if status:
        items = [i for i in items if i.get("status") == status.lower()]
    if owasp_mcp:
        items = [i for i in items if owasp_mcp.upper() in (i.get("owasp_mcp") or [])]

    total = len(items)
    return {
        "total":   total,
        "offset":  offset,
        "limit":   limit,
        "records": items[offset: offset + limit],
    }


@router.get("/search")
def search_records(
    q:     str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(20, ge=1, le=100),
):
    """Full-text search across AVE records."""
    records = get_all()
    query   = q.lower()
    scored: list[tuple[int, dict]] = []

    for r in records.values():
        score = 0
        if query in (r.get("ave_id")             or "").lower(): score += 10
        if query in (r.get("title")              or "").lower(): score += 5
        if query in (r.get("attack_class")       or "").lower(): score += 4
        if query in (r.get("description")        or "").lower(): score += 2
        if query in (r.get("behavioral_fingerprint") or "").lower(): score += 1
        if score > 0:
            scored.append((score, to_summary(r)))

    scored.sort(key=lambda x: x[0], reverse=True)
    return {
        "query":   q,
        "total":   len(scored),
        "records": [s for _, s in scored[:limit]],
    }


@router.get("/{ave_id}")
def get_record(ave_id: str):
    """Get a full AVE record by ID."""
    record = get_one(ave_id)
    if not record:
        raise HTTPException(
            status_code = 404,
            detail = {
                "error":       f"AVE record not found: {ave_id}",
                "hint":        "Browse all records at /records",
                "piranha_url": "https://api.piranha.bawbel.io/records",
            },
        )
    enriched = dict(record)
    enriched["piranha_url"]  = f"https://api.piranha.bawbel.io/records/{ave_id}"
    enriched["severity"]     = severity_from_cvss(record.get("cvss_ai_score", 0))
    enriched["owasp_mcp"]    = get_owasp_mcp(ave_id)
    return enriched


@router.get("/{ave_id}/detection")
def get_detection(ave_id: str):
    """Get detection guidance for a specific AVE record."""
    record = get_one(ave_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"AVE record not found: {ave_id}")

    return {
        "ave_id":                    record.get("ave_id"),
        "title":                     record.get("title"),
        "behavioral_fingerprint":    record.get("behavioral_fingerprint"),
        "behavioral_vector":         record.get("behavioral_vector", []),
        "detection_methodology":     record.get("detection_methodology"),
        "indicators_of_compromise":  record.get("indicators_of_compromise", []),
        "scan_command":              "pip install bawbel-scanner && bawbel scan ./",
        "piranha_url":               f"https://api.piranha.bawbel.io/records/{ave_id}",
    }
