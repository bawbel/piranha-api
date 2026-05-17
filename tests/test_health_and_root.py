"""
Integration tests - /, /health, legacy aliases, and on-demand /scan.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestRoot:
    def test_root_returns_200(self, app_client):
        r = app_client.get("/")
        assert r.status_code == 200

    def test_root_fields(self, app_client):
        body = app_client.get("/").json()
        for field in ("name", "version", "scanner_version", "records",
                      "detection_rules", "endpoints", "links", "timestamp"):
            assert field in body, f"missing field: {field}"

    def test_root_name_is_piranhadb(self, app_client):
        assert app_client.get("/").json()["name"] == "PiranhaDB"

    def test_root_records_count_matches_loaded(self, app_client):
        body = app_client.get("/").json()
        assert body["records"] == 3

    def test_root_detection_rules_is_positive_int(self, app_client):
        assert app_client.get("/").json()["detection_rules"] > 0

    def test_root_links_no_bawbel_ave(self, app_client):
        links = app_client.get("/").json()["links"]
        for url in links.values():
            assert "bawbel-ave" not in url, f"stale bawbel-ave ref in: {url}"

    def test_root_free_and_no_auth(self, app_client):
        body = app_client.get("/").json()
        assert body["free"] is True
        assert body["auth"] is None

    def test_root_endpoints_include_feedback(self, app_client):
        endpoints = app_client.get("/").json()["endpoints"]
        assert "false_positive" in endpoints or any(
            "feedback" in v for v in endpoints.values()
        )


class TestHealth:
    def test_health_returns_200(self, app_client):
        r = app_client.get("/health")
        assert r.status_code == 200

    def test_health_status_ok(self, app_client):
        assert app_client.get("/health").json()["status"] == "ok"

    def test_health_fields(self, app_client):
        body = app_client.get("/health").json()
        for field in ("status", "records", "version", "scanner_version",
                      "detection_rules", "cache", "timestamp"):
            assert field in body, f"missing field: {field}"

    def test_health_records_count(self, app_client):
        assert app_client.get("/health").json()["records"] == 3

    def test_health_cache_info_present(self, app_client):
        cache = app_client.get("/health").json()["cache"]
        assert "connected" in cache

    def test_health_versions_match_config(self, app_client):
        body = app_client.get("/health").json()
        assert body["version"]         == "1.2.1"
        assert body["scanner_version"] == "1.2.1"


class TestLegacyAliases:
    def test_legacy_ave_list(self, app_client):
        r = app_client.get("/ave")
        assert r.status_code == 200
        # Should return same shape as /records
        body = r.json()
        assert "total"   in body
        assert "records" in body

    def test_legacy_ave_get(self, app_client):
        r = app_client.get("/ave/AVE-2026-00001")
        assert r.status_code == 200
        assert r.json()["ave_id"] == "AVE-2026-00001"

    def test_legacy_ave_get_missing_returns_404(self, app_client):
        r = app_client.get("/ave/AVE-2026-99999")
        assert r.status_code == 404


class TestOnDemandScan:
    def test_scan_requires_url_or_content(self, app_client):
        r = app_client.post("/scan", json={})
        assert r.status_code == 422

    def test_scan_content_too_large_returns_422(self, app_client):
        big = "x" * (102401)  # 100KB + 1 byte
        r = app_client.post("/scan", json={"content": big})
        assert r.status_code == 422

    def test_scan_with_content_calls_bawbel(self, app_client):
        """
        Bawbel may not be installed in the test environment.
        We mock the subprocess to return a clean JSON result.
        """
        mock_output = '[{"findings":[],"toxic_flows":[],"risk_score":0,"max_severity":null,"scan_time_ms":12,"component_type":"skill"}]'
        with patch("routers.submit.subprocess.run") as mock_run:
            mock_run.return_value.stdout    = mock_output
            mock_run.return_value.returncode = 0
            r = app_client.post("/scan", json={"content": "fetch from https://rentry.co/test"})
        assert r.status_code == 200
        body = r.json()
        assert "submission_id"    in body
        assert "findings_count"   in body
        assert "toxic_flows_count" in body
        assert "result_url"       in body

    def test_scan_result_url_format(self, app_client):
        mock_output = '[{"findings":[],"toxic_flows":[],"risk_score":0,"max_severity":null,"scan_time_ms":5,"component_type":"skill"}]'
        with patch("routers.submit.subprocess.run") as mock_run:
            mock_run.return_value.stdout = mock_output
            body = app_client.post("/scan", json={"content": "test"}).json()
        assert body["result_url"].startswith("https://api.piranha.bawbel.io/scan/")

    def test_scan_submission_retrievable(self, app_client):
        mock_output = '[{"findings":[],"toxic_flows":[],"risk_score":0,"max_severity":null,"scan_time_ms":5,"component_type":"skill"}]'
        with patch("routers.submit.subprocess.run") as mock_run:
            mock_run.return_value.stdout = mock_output
            sid = app_client.post("/scan", json={"content": "test"}).json()["submission_id"]
        r = app_client.get(f"/scan/{sid}")
        assert r.status_code == 200
        assert r.json()["submission_id"] == sid

    def test_scan_get_missing_returns_404(self, app_client):
        r = app_client.get("/scan/000000000000")
        assert r.status_code == 404

    def test_scan_get_invalid_id_returns_400(self, app_client):
        r = app_client.get("/scan/bad;id!here")
        assert r.status_code == 400

    def test_scan_scanner_timeout_returns_200_with_error(self, app_client):
        """Timeout must return 200 with error field, not 500."""
        import subprocess as _sub
        with patch("routers.submit.subprocess.run",
                   side_effect=_sub.TimeoutExpired(cmd="bawbel", timeout=30)):
            r = app_client.post("/scan", json={"content": "test content here"})
        assert r.status_code == 200
        assert r.json()["error"] is not None


class TestSyncRecordsScript:
    def test_sync_falls_back_on_network_error(self, tmp_path):
        """sync() must return 0 and not raise when GitHub is unreachable."""
        import importlib.util
        import urllib.error
        from unittest.mock import patch

        spec = importlib.util.spec_from_file_location(
            "sync_records",
            PROJECT_ROOT / "sync_records.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        import os
        os.environ["RECORDS_DIR"] = str(tmp_path / "records")

        # Simulate network failure regardless of whether the real repo exists
        with patch("urllib.request.urlopen",
                   side_effect=OSError("simulated network failure")):
            count = mod.sync()

        assert count == 0
        os.environ.pop("RECORDS_DIR", None)
