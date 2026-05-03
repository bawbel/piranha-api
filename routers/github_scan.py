"""
PiranhaDB — GitHub skill repo scan router.

GET /github-scan/{owner}/{repo}          — latest scan of a skills repo
GET /github-scan/{owner}/{repo}/history  — scan history
GET /github-scan/sources                 — official repos we scan
"""

from fastapi import APIRouter, HTTPException, Path
from store.scan_store import get_latest, get_history
from config import GITHUB_SKILL_REPOS

router = APIRouter(prefix="/github-scan", tags=["GitHub Skill Scans"])


def _source_key(owner: str, repo: str) -> str:
    """Normalise owner/repo to a scan store source key."""
    safe_owner = "".join(c if c.isalnum() or c == "-" else "-" for c in owner.lower())
    safe_repo  = "".join(c if c.isalnum() or c == "-" else "-" for c in repo.lower())
    return f"github-{safe_owner}-{safe_repo}"


@router.get("/sources")
def list_sources():
    """List GitHub skill repos we scan on a scheduled basis."""
    sources = []
    for repo in GITHUB_SKILL_REPOS:
        owner, name = repo.split("/", 1)
        key    = _source_key(owner, name)
        latest = get_latest(key)
        sources.append({
            "repo":       repo,
            "github_url": f"https://github.com/{repo}",
            "has_data":   latest is not None,
            "last_scan":  latest.get("scan_date") if latest else None,
            "files_scanned": latest.get("files_scanned") if latest else None,
        })
    return {"sources": sources}


@router.get("/{owner}/{repo}")
def get_latest_scan(
    owner: str = Path(..., description="GitHub owner e.g. 'google'"),
    repo:  str = Path(..., description="Repository name e.g. 'skills'"),
):
    """Get the latest scan results for a GitHub skills repo."""
    key    = _source_key(owner, repo)
    result = get_latest(key)
    if not result:
        raise HTTPException(
            status_code = 404,
            detail = {
                "error":      f"No scan data for {owner}/{repo}",
                "hint":       (
                    "Official repos (google/skills, microsoft/skills, vercel/skills) "
                    "are scanned weekly. Other repos are not scanned automatically."
                ),
                "scan_now":   f"POST /scan with repo URL to trigger an on-demand scan",
            }
        )
    return result


@router.get("/{owner}/{repo}/history")
def get_scan_history(
    owner: str = Path(...),
    repo:  str = Path(...),
    limit: int = 12,
):
    """Get scan history for a GitHub skills repo."""
    key     = _source_key(owner, repo)
    history = get_history(key, limit=limit)
    if not history:
        raise HTTPException(
            status_code = 404,
            detail = {"error": f"No scan history for {owner}/{repo}"}
        )
    return {
        "repo":    f"{owner}/{repo}",
        "periods": len(history),
        "history": history,
    }
