"""
PiranhaDB: Registry scan router.

GET /registry-scan/latest          : latest scan for a registry
GET /registry-scan/history         : weekly trend data
GET /registry-scan/sources         : available scan sources
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Request
from store.scan_store import get_latest, get_history, save_scan
from config import PIRANHA_INGEST_TOKEN

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


@router.post("/ingest")
async def ingest_scan(
    request: Request,
    source: str = Query("smithery", description="smithery | mcp-registry"),
):
    """
    Ingest a registry scan result from an external scan script.

    Accepts the full JSON output from scan_smithery.py or any compatible
    scan script and saves it to the scan store for history and trending.

    Auth: PIRANHA_INGEST_TOKEN env var must match X-Ingest-Token header.
    Set PIRANHA_INGEST_TOKEN in Railway env vars.
    """
    token = request.headers.get("X-Ingest-Token", "")
    if PIRANHA_INGEST_TOKEN and token != PIRANHA_INGEST_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid ingest token")

    s      = _validate_source(source)
    body   = await request.json()

    # Normalise field names from scan_smithery.py output
    data = {
        "scan_source":              s,
        "scan_date":                body.get("scan_date"),
        "scanner_version":          body.get("scanner_version"),
        "servers_scanned":          body.get("servers_scanned", 0),
        "servers_with_findings":    body.get("servers_with_findings", 0),
        "servers_clean":            body.get("servers_clean", 0),
        "servers_with_toxic_flows": body.get("servers_with_toxic_flows", 0),
        "total_findings":           body.get("total_findings", 0),
        "total_toxic_flows":        body.get("total_toxic_flows", 0),
        "flaw_rate_pct":            body.get("flaw_rate_pct", 0),
        "by_severity":              body.get("by_severity", {}),
        "top_ave_ids":              body.get("top_ave_ids", []),
        "top_owasp_mcp":            body.get("top_owasp_mcp", []),
    }

    save_scan(s, data)

    return {
        "status":           "ok",
        "source":           s,
        "servers_scanned":  data["servers_scanned"],
        "flaw_rate_pct":    data["flaw_rate_pct"],
        "message":          f"Scan result ingested for source: {s}",
    }
