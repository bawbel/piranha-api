"""
Integration tests - /registry-scan, /github-scan, and /stats endpoints.
"""

import json
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_smithery_scan(scans_dir: Path, **overrides) -> dict:
    """Write a smithery scan result to the tmp scans dir."""
    from helpers import make_scan_result
    src_dir = scans_dir / "smithery"
    src_dir.mkdir(parents=True, exist_ok=True)
    data = {**make_scan_result("smithery"), **overrides}
    path = src_dir / "2026-05-17T08:00:00.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return data


def _seed_github_scan(scans_dir: Path, owner: str, repo: str) -> dict:
    key     = f"github-{owner}-{repo}"
    src_dir = scans_dir / key
    src_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "scan_source":    key,
        "scan_date":      "2026-05-17T08:00:00",
        "files_scanned":  50,
        "total_findings": 3,
        "findings":       [],
    }
    path = src_dir / "2026-05-17T08:00:00.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return data


# ---------------------------------------------------------------------------
# /registry-scan
# ---------------------------------------------------------------------------

class TestRegistryScanSources:
    def test_sources_returns_200(self, app_client):
        r = app_client.get("/registry-scan/sources")
        assert r.status_code == 200

    def test_sources_lists_smithery_and_mcp_registry(self, app_client):
        body = app_client.get("/registry-scan/sources").json()
        sources = [s["source"] for s in body["sources"]]
        assert "smithery"     in sources
        assert "mcp-registry" in sources

    def test_sources_has_data_flag(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir)
        r = app_client.get("/registry-scan/sources")
        for s in r.json()["sources"]:
            if s["source"] == "smithery":
                assert s["has_data"] is True


class TestRegistryScanLatest:
    def test_latest_404_when_no_data(self, app_client):
        r = app_client.get("/registry-scan/latest?source=smithery")
        assert r.status_code == 404

    def test_latest_returns_data_after_seed(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir)
        r = app_client.get("/registry-scan/latest?source=smithery")
        assert r.status_code == 200

    def test_latest_response_fields(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir)
        body = app_client.get("/registry-scan/latest?source=smithery").json()
        for field in ("scan_source", "scan_date", "servers_scanned",
                      "servers_with_findings", "total_findings", "flaw_rate_pct"):
            assert field in body, f"missing field: {field}"

    def test_latest_invalid_source_returns_400(self, app_client):
        r = app_client.get("/registry-scan/latest?source=unknown-registry")
        assert r.status_code == 400

    def test_latest_default_source_is_smithery(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir)
        r_explicit = app_client.get("/registry-scan/latest?source=smithery")
        r_default  = app_client.get("/registry-scan/latest")
        assert r_explicit.status_code == r_default.status_code


class TestRegistryScanHistory:
    def test_history_404_when_no_data(self, app_client):
        r = app_client.get("/registry-scan/history?source=smithery")
        assert r.status_code == 404

    def test_history_returns_data_after_seed(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir)
        r = app_client.get("/registry-scan/history?source=smithery")
        assert r.status_code == 200

    def test_history_response_shape(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir)
        body = app_client.get("/registry-scan/history?source=smithery").json()
        assert "source"  in body
        assert "periods" in body
        assert "trend"   in body
        assert isinstance(body["trend"], list)

    def test_history_trend_entry_fields(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir)
        trend = app_client.get("/registry-scan/history?source=smithery").json()["trend"]
        entry = trend[0]
        for field in ("scan_date", "servers_scanned", "servers_with_findings",
                      "total_findings", "flaw_rate_pct"):
            assert field in entry, f"missing field: {field}"

    def test_history_limit_param(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        src_dir = scans_dir / "smithery"
        src_dir.mkdir(parents=True, exist_ok=True)
        from helpers import make_scan_result
        for i in range(5):
            data = make_scan_result("smithery")
            path = src_dir / f"2026-05-{i + 1:02d}T08:00:00.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        body = app_client.get("/registry-scan/history?source=smithery&limit=2").json()
        assert body["periods"] == 2
        assert len(body["trend"]) == 2

    def test_history_flaw_rate_computed(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir, servers_scanned=100, servers_with_findings=20)
        trend = app_client.get("/registry-scan/history?source=smithery").json()["trend"]
        assert trend[0]["flaw_rate_pct"] == 20.0


# ---------------------------------------------------------------------------
# /github-scan
# ---------------------------------------------------------------------------

class TestGithubScan:
    def test_sources_returns_200(self, app_client):
        r = app_client.get("/github-scan/sources")
        assert r.status_code == 200

    def test_latest_404_when_no_data(self, app_client):
        r = app_client.get("/github-scan/google/skills")
        assert r.status_code == 404

    def test_latest_returns_data_after_seed(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_github_scan(scans_dir, "google", "skills")
        r = app_client.get("/github-scan/google/skills")
        assert r.status_code == 200

    def test_history_404_when_no_data(self, app_client):
        r = app_client.get("/github-scan/google/skills/history")
        assert r.status_code == 404

    def test_history_returns_data_after_seed(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_github_scan(scans_dir, "google", "skills")
        r = app_client.get("/github-scan/google/skills/history")
        assert r.status_code == 200
        body = r.json()
        assert "repo"    in body
        assert "periods" in body
        assert "history" in body

    def test_source_key_normalises_special_chars(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        # repo names with dots/underscores should not blow up
        r = app_client.get("/github-scan/my.org/my_repo")
        assert r.status_code == 404  # 404 not 500 - normalisation worked


# ---------------------------------------------------------------------------
# /stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_basic_stats_returns_200(self, app_client):
        r = app_client.get("/stats")
        assert r.status_code == 200

    def test_basic_stats_fields(self, app_client):
        body = app_client.get("/stats").json()
        for field in ("total_records", "by_severity", "by_component_type",
                      "by_attack_class", "scanner_version", "detection_rules"):
            assert field in body, f"missing field: {field}"

    def test_basic_stats_record_count(self, app_client):
        body = app_client.get("/stats").json()
        assert body["total_records"] == 3

    def test_basic_stats_severity_breakdown(self, app_client):
        body = app_client.get("/stats").json()
        total = sum(body["by_severity"].values())
        assert total == 3

    def test_ecosystem_stats_returns_200(self, app_client):
        r = app_client.get("/stats/ecosystem")
        assert r.status_code == 200

    def test_ecosystem_stats_fields(self, app_client):
        body = app_client.get("/stats/ecosystem").json()
        for field in ("generated_at", "scanner_version", "detection_rules",
                      "ave_records", "registry_scans", "github_scans", "links"):
            assert field in body, f"missing field: {field}"

    def test_ecosystem_stats_ave_records(self, app_client):
        body = app_client.get("/stats/ecosystem").json()
        assert body["ave_records"]["total"] == 3

    def test_ecosystem_stats_includes_registry_when_seeded(self, app_client, tmp_dirs):
        _, scans_dir = tmp_dirs
        _seed_smithery_scan(scans_dir)
        body = app_client.get("/stats/ecosystem").json()
        assert body["registry_scans"]["total_servers_scanned"] == 100
        assert body["registry_scans"]["total_findings"] == 25

    def test_ecosystem_links_reference_correct_repos(self, app_client):
        body = app_client.get("/stats/ecosystem").json()
        links = body["links"]
        assert "bawbel/ave" in links["ave_standard"]
        assert "bawbel-ave" not in links["ave_standard"]
        assert "bawbel" in links["scanner"]
