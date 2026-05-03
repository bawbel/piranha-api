"""
PiranhaDB — Registry scan router.

GET /registry-scan/latest           — latest scan for a registry
GET /registry-scan/history          — weekly trend data
GET /registry-scan/sources          — available scan sources
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from store.scan_store import get_latest, get_history

router = APIRouter(prefix="/registry-scan", tags=["Registry Scans"])

VALID_SOURCES = {"smithery", "mcp-registry"}


def _validate_source(source: str) -> str:
    s = source.lower().strip()
    if s not in VALID_SOURCES:
        raise HTTPException(
            status_code = 400,
            detail = {
                "error":   f"Unknown source: {source}",
                "valid":   sorted(VALID_SOURCES),
            }
        )
    return s


@router.get("/sources")
def list_sources():
    """List available registry scan sources."""
    sources = []
    for s in sorted(VALID_SOURCES):
        latest = get_latest(s)
        sources.append({
            "source":      s,
            "has_data":    latest is not None,
            "last_scan":   latest.get("scan_date") if latest else None,
            "server_count": latest.get("servers_scanned") if latest else None,
        })
    return {"sources": sources}


@router.get("/latest")
def latest_scan(
    source: str = Query("smithery", description="smithery | mcp-registry"),
):
    """Get the latest scan results for a registry."""
    s      = _validate_source(source)
    result = get_latest(s)
    if not result:
        raise HTTPException(
            status_code = 404,
            detail = {
                "error":  f"No scan data for source: {source}",
                "hint":   "Scans run weekly. Check back later.",
            }
        )
    return result


@router.get("/history")
def scan_history(
    source: str = Query("smithery", description="smithery | mcp-registry"),
    limit:  int = Query(12, ge=1, le=52, description="Number of historical scans (max 52)"),
):
    """Get weekly scan history for trend analysis."""
    s       = _validate_source(source)
    history = get_history(s, limit=limit)
    if not history:
        raise HTTPException(
            status_code = 404,
            detail = {"error": f"No scan history for source: {source}"}
        )

    # Build trend-friendly summary
    trend = []
    for scan in history:
        trend.append({
            "scan_date":              scan.get("scan_date"),
            "servers_scanned":        scan.get("servers_scanned", 0),
            "servers_with_findings":  scan.get("servers_with_findings", 0),
            "total_findings":         scan.get("total_findings", 0),
            "flaw_rate_pct":          round(
                scan.get("servers_with_findings", 0) /
                max(scan.get("servers_scanned", 1), 1) * 100, 1
            ),
        })

    return {
        "source":  source,
        "periods": len(trend),
        "trend":   trend,
    }
