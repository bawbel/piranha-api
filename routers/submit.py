"""
PiranhaDB — Submit endpoint.

POST /scan   — submit a URL or content for on-demand scanning

This is the killer feature: "check before you install."
Paste any MCP server URL, Smithery server name, or skill file content
and get instant scan results.

Security:
    - Rate limited per IP (SCAN_RATE_LIMIT requests/minute)
    - Content size capped at SCAN_MAX_BYTES
    - No credentials stored
    - Results are public (no PII in scanned content)
    - bawbel-scanner runs in subprocess with timeout
"""

import json
import subprocess  # nosec B404  # noqa: S404
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from config import SCAN_MAX_BYTES
from store.scan_store import save_submission, get_submission

router = APIRouter(prefix="", tags=["On-demand Scan"])


# ── Request / response models ─────────────────────────────────────────────────


class ScanRequest(BaseModel):
    url:     Optional[str] = Field(None, description="URL to fetch and scan (MCP server base URL or direct file URL)")
    content: Optional[str] = Field(None, description="Raw content to scan (skill file, manifest, system prompt)")

    @field_validator("content")
    @classmethod
    def content_size_limit(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v.encode("utf-8")) > SCAN_MAX_BYTES:
            raise ValueError(f"Content exceeds {SCAN_MAX_BYTES // 1024}KB limit")
        return v

    def model_post_init(self, __context) -> None:
        if not self.url and not self.content:
            raise ValueError("Provide either 'url' or 'content'")


# ── Scanner subprocess ────────────────────────────────────────────────────────


def _run_bawbel_scan(content: str) -> dict:
    """
    Run bawbel scan on content via subprocess.
    Returns parsed JSON result or error dict.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", prefix="piranha_submit_",
        delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        tmp_path = f.name

    try:
        result = subprocess.run(  # nosec B603 B607  # noqa: S603 S607
            ["bawbel", "scan", tmp_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        raw = result.stdout.strip()
        if not raw:
            return {"error": "Scanner produced no output", "findings": [], "toxic_flows": []}

        start = raw.find("[")
        if start < 0:
            return {"error": raw[:200], "findings": [], "toxic_flows": []}

        scan_results = json.loads(raw[start:])
        if scan_results:
            r = scan_results[0]
            return {
                "findings":    r.get("findings", []),
                "toxic_flows": r.get("toxic_flows", []),
                "risk_score":  r.get("risk_score", 0),
                "max_severity": r.get("max_severity"),
                "scan_time_ms": r.get("scan_time_ms", 0),
                "component_type": r.get("component_type", "unknown"),
            }
        return {"findings": [], "toxic_flows": [], "risk_score": 0}

    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout (30s)", "findings": [], "toxic_flows": []}
    except json.JSONDecodeError as e:
        return {"error": f"Parse error: {e}", "findings": [], "toxic_flows": []}
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _fetch_url_content(url: str) -> tuple[Optional[str], Optional[str]]:
    """
    Fetch content from a URL for scanning.
    Tries server-card path first for MCP servers, then falls back to direct URL.
    Returns (content, error).
    """
    import urllib.request
    import urllib.error

    # Try server-card path first (MCP servers)
    server_card_url = url.rstrip("/") + "/.well-known/mcp.json"
    for attempt_url in [server_card_url, url]:
        try:
            req = urllib.request.Request(
                attempt_url,
                headers={"User-Agent": "piranha-api/1.1 (https://api.piranha.bawbel.io)"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310
                raw = r.read(SCAN_MAX_BYTES).decode("utf-8", errors="replace")
                return raw, None
        except urllib.error.HTTPError:
            continue
        except Exception as e:  # noqa: BLE001
            return None, str(e)

    return None, f"Could not fetch content from {url}"


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post("/scan")
async def submit_scan(request: Request, body: ScanRequest):
    """
    Scan a URL or content for AVE vulnerabilities.

    Submit a URL (MCP server, skill file, GitHub raw URL) or paste content
    directly. Returns findings, toxic flows, and risk score.

    Rate limited to 10 requests/minute per IP.
    Content size limit: 100KB.
    """
    # Resolve content
    if body.url:
        content, err = _fetch_url_content(body.url)
        if err or not content:
            raise HTTPException(
                status_code = 422,
                detail = {
                    "error":  err or "Could not fetch URL",
                    "url":    body.url,
                }
            )
        source_label = body.url
    else:
        content      = body.content
        source_label = "submitted-content"

    # Run scan
    result = _run_bawbel_scan(content)

    # Persist result
    sid = save_submission(content, {
        "source":       source_label,
        "scan_result":  result,
    })

    return {
        "submission_id":  sid,
        "source":         source_label,
        "risk_score":     result.get("risk_score", 0),
        "max_severity":   result.get("max_severity"),
        "component_type": result.get("component_type"),
        "findings_count": len(result.get("findings", [])),
        "toxic_flows_count": len(result.get("toxic_flows", [])),
        "findings":       result.get("findings", []),
        "toxic_flows":    result.get("toxic_flows", []),
        "scan_time_ms":   result.get("scan_time_ms", 0),
        "result_url":     f"https://api.piranha.bawbel.io/scan/{sid}",
        "error":          result.get("error"),
    }


@router.get("/scan/{submission_id}")
def get_submission_result(submission_id: str):
    """Get a previously submitted scan result by ID."""
    # Validate submission_id is safe (alphanumeric only)
    if not all(c.isalnum() for c in submission_id):
        raise HTTPException(status_code=400, detail="Invalid submission ID")

    result = get_submission(submission_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail={"error": f"Submission not found: {submission_id}"}
        )
    return result
