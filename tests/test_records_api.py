"""
Integration tests - /records endpoints.

Uses TestClient with isolated tmp filesystem (via app_client fixture).
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestRecordsList:
    def test_list_returns_200(self, app_client):
        r = app_client.get("/records")
        assert r.status_code == 200

    def test_list_response_shape(self, app_client):
        r = app_client.get("/records")
        body = r.json()
        assert "total"   in body
        assert "records" in body
        assert "offset"  in body
        assert "limit"   in body

    def test_list_returns_all_records(self, app_client):
        r = app_client.get("/records")
        assert r.json()["total"] == 3

    def test_filter_by_severity_critical(self, app_client):
        r = app_client.get("/records?severity=CRITICAL")
        body = r.json()
        assert body["total"] == 1
        assert all(rec["severity"] == "CRITICAL" for rec in body["records"])

    def test_filter_by_severity_case_insensitive(self, app_client):
        r = app_client.get("/records?severity=critical")
        assert r.json()["total"] == 1

    def test_filter_by_component_type(self, app_client):
        r = app_client.get("/records?component_type=mcp_server")
        body = r.json()
        assert body["total"] == 1
        assert body["records"][0]["component_type"] == "mcp_server"

    def test_filter_by_status_deprecated(self, app_client):
        r = app_client.get("/records?status=deprecated")
        body = r.json()
        assert body["total"] == 1
        assert body["records"][0]["status"] == "deprecated"

    def test_filter_by_owasp_mcp(self, app_client):
        # All 3 test records have MCP05 in owasp_mapping
        r = app_client.get("/records?owasp_mcp=MCP05")
        assert r.json()["total"] >= 1

    def test_filter_combined(self, app_client):
        r = app_client.get("/records?severity=HIGH&component_type=mcp_server")
        body = r.json()
        for rec in body["records"]:
            assert rec["severity"]        == "HIGH"
            assert rec["component_type"]  == "mcp_server"

    def test_pagination_limit(self, app_client):
        r = app_client.get("/records?limit=2")
        body = r.json()
        assert len(body["records"]) == 2
        assert body["total"] == 3  # total unchanged

    def test_pagination_offset(self, app_client):
        r_all    = app_client.get("/records?limit=3&offset=0").json()["records"]
        r_offset = app_client.get("/records?limit=3&offset=1").json()["records"]
        assert len(r_offset) == 2
        assert r_offset[0]["ave_id"] == r_all[1]["ave_id"]

    def test_summary_record_has_required_fields(self, app_client):
        rec = app_client.get("/records").json()["records"][0]
        for field in ("ave_id", "title", "severity", "aivss_score",
                      "component_type", "status", "piranha_url"):
            assert field in rec, f"missing field: {field}"

    def test_piranha_url_format(self, app_client):
        rec = app_client.get("/records").json()["records"][0]
        assert rec["piranha_url"].startswith("https://api.piranha.bawbel.io/records/AVE-")


class TestRecordsSearch:
    def test_search_by_title_keyword(self, app_client):
        r = app_client.get("/records/search?q=vulnerability")
        body = r.json()
        assert body["total"] >= 1

    def test_search_by_attack_class(self, app_client):
        r = app_client.get("/records/search?q=Tool+Poisoning")
        body = r.json()
        assert body["total"] >= 1
        assert "AVE-2026-00002" in [rec["ave_id"] for rec in body["records"]]

    def test_search_returns_query_field(self, app_client):
        r = app_client.get("/records/search?q=test")
        assert r.json()["query"] == "test"

    def test_search_no_results(self, app_client):
        r = app_client.get("/records/search?q=xyzzy99nonexistent")
        assert r.json()["total"] == 0

    def test_search_too_short_query_returns_422(self, app_client):
        r = app_client.get("/records/search?q=x")
        assert r.status_code == 422

    def test_search_missing_q_returns_422(self, app_client):
        r = app_client.get("/records/search")
        assert r.status_code == 422

    def test_search_limit_respected(self, app_client):
        r = app_client.get("/records/search?q=test&limit=1")
        assert len(r.json()["records"]) <= 1


class TestRecordDetail:
    def test_get_existing_record(self, app_client):
        r = app_client.get("/records/AVE-2026-00001")
        assert r.status_code == 200

    def test_get_record_fields(self, app_client):
        body = app_client.get("/records/AVE-2026-00001").json()
        assert body["ave_id"]                  == "AVE-2026-00001"
        assert "behavioral_fingerprint"        in body
        assert "indicators_of_compromise"      in body
        assert "remediation"                   in body
        assert "severity"                      in body
        assert "owasp_mcp"                     in body
        assert "piranha_url"                   in body

    def test_get_record_case_insensitive_id(self, app_client):
        r = app_client.get("/records/ave-2026-00001")
        assert r.status_code == 200

    def test_get_missing_record_returns_404(self, app_client):
        r = app_client.get("/records/AVE-2026-99999")
        assert r.status_code == 404

    def test_get_record_404_body(self, app_client):
        body = app_client.get("/records/AVE-2026-99999").json()
        assert "error" in body["detail"]

    def test_get_record_owasp_mcp_is_list(self, app_client):
        body = app_client.get("/records/AVE-2026-00001").json()
        assert isinstance(body["owasp_mcp"], list)


class TestDetectionEndpoint:
    def test_detection_returns_200(self, app_client):
        r = app_client.get("/records/AVE-2026-00001/detection")
        assert r.status_code == 200

    def test_detection_fields(self, app_client):
        body = app_client.get("/records/AVE-2026-00001/detection").json()
        for field in ("ave_id", "title", "behavioral_fingerprint",
                      "detection_methodology", "indicators_of_compromise",
                      "scan_command", "piranha_url"):
            assert field in body, f"missing field: {field}"

    def test_detection_scan_command_references_bawbel(self, app_client):
        body = app_client.get("/records/AVE-2026-00001/detection").json()
        assert "bawbel" in body["scan_command"]

    def test_detection_missing_record_returns_404(self, app_client):
        r = app_client.get("/records/AVE-2026-99999/detection")
        assert r.status_code == 404
