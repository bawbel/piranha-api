"""Shared test data builders - importable without pytest."""


def make_record(n: int, **overrides) -> dict:
    ave_id = f"AVE-2026-{n:05d}"
    base = {
        "ave_id":                ave_id,
        "schema_version":        "1.0.0",
        "component_type":        "skill",
        "title":                 f"Test vulnerability {n}",
        "attack_class":          "Prompt Injection",
        "description":           f"Description for {ave_id}",
        "aivss_score":           7.5,
        "aivss": {
            "cvss_base":         7.0,
            "aars":              1.07,
            "thm":               1.0,
            "mitigation_factor": 1.0,
            "aivss_severity":    "HIGH",
            "spec_version":      "0.8",
        },
        "owasp_mapping":         ["MCP05", "MCP03"],
        "behavioral_fingerprint": f"Fingerprint for {ave_id}",
        "behavioral_vector":     [],
        "mutation_count":        5,
        "detection_methodology": "Static pattern matching.",
        "indicators_of_compromise": ["IOC one", "IOC two"],
        "remediation":           "Remove the skill.",
        "status":                "active",
        "published":             "2026-05-01T09:00:00Z",
        "last_updated":          "2026-05-01T09:00:00Z",
        "references":            ["https://github.com/bawbel/ave/blob/main/SPEC.md"],
    }
    base.update(overrides)
    return base


def make_scan_result(source: str = "smithery") -> dict:
    return {
        "scan_source":              source,
        "scan_date":                "2026-05-17T08:00:00",
        "scanner_version":          "1.2.1",
        "servers_scanned":          100,
        "servers_with_findings":    18,
        "servers_clean":            82,
        "servers_with_toxic_flows": 3,
        "total_findings":           25,
        "total_toxic_flows":        4,
        "flaw_rate_pct":            18.0,
        "by_severity": {
            "CRITICAL": 2,
            "HIGH":     8,
            "MEDIUM":   10,
            "LOW":      5,
        },
        "top_ave_ids": [
            {"ave_id": "AVE-2026-00001", "count": 5, "title": "Test vuln"},
        ],
        "top_owasp_mcp": ["MCP05", "MCP03"],
    }
