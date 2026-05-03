"""
PiranhaDB — Ecosystem stats router.

GET /stats           — aggregate stats across all sources (legacy compat)
GET /stats/ecosystem — full ecosystem stats including registry scans
"""

from datetime import datetime, timezone
from fastapi import APIRouter
from store.records_store import get_all, severity_from_cvss, count as record_count
from store.scan_store import get_latest

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("")
def basic_stats():
    """Basic AVE record statistics (backwards compatible with v0.1)."""
    records = get_all()
    items   = list(records.values())

    by_severity: dict[str, int] = {}
    by_type:     dict[str, int] = {}
    by_class:    dict[str, int] = {}
    total_mutations = 0

    for r in items:
        sev = severity_from_cvss(r.get("cvss_ai_score", 0))
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


@router.get("/ecosystem")
def ecosystem_stats():
    """
    Full ecosystem stats — AVE records + registry scan results.

    Aggregates across all scan sources to provide the PiranhaDB
    dashboard numbers.
    """
    # AVE records
    records = get_all()
    items   = list(records.values())

    by_severity: dict[str, int] = {}
    for r in items:
        sev = severity_from_cvss(r.get("cvss_ai_score", 0))
        by_severity[sev] = by_severity.get(sev, 0) + 1

    # Registry scan summaries
    registry_summaries: list[dict] = []
    total_servers_scanned = 0
    total_findings        = 0

    for source in ["smithery", "mcp-registry"]:
        latest = get_latest(source)
        if latest:
            scanned  = latest.get("servers_scanned", 0)
            findings = latest.get("total_findings", 0)
            total_servers_scanned += scanned
            total_findings        += findings
            registry_summaries.append({
                "source":               source,
                "last_scan":            latest.get("scan_date"),
                "servers_scanned":      scanned,
                "servers_with_findings": latest.get("servers_with_findings", 0),
                "total_findings":       findings,
                "flaw_rate_pct":        round(
                    latest.get("servers_with_findings", 0) /
                    max(scanned, 1) * 100, 1
                ),
            })

    # GitHub skill repos
    github_summaries: list[dict] = []
    for repo in ["google-skills", "microsoft-skills", "vercel-skills"]:
        latest = get_latest(f"github-{repo}")
        if latest:
            github_summaries.append({
                "repo":          repo.replace("-", "/", 1),
                "last_scan":     latest.get("scan_date"),
                "files_scanned": latest.get("files_scanned", 0),
                "findings":      latest.get("total_findings", 0),
            })

    return {
        "generated_at":           datetime.now(timezone.utc).isoformat(),
        "ave_records": {
            "total":       len(items),
            "by_severity": by_severity,
        },
        "registry_scans": {
            "total_servers_scanned": total_servers_scanned,
            "total_findings":        total_findings,
            "sources":               registry_summaries,
        },
        "github_scans": {
            "repos": github_summaries,
        },
        "links": {
            "scanner":      "https://github.com/bawbel/bawbel-scanner",
            "ave_standard": "https://github.com/bawbel/bawbel-ave",
            "piranha_api":  "https://api.piranha.bawbel.io",
            "docs":         "https://bawbel.io/docs",
        },
    }
