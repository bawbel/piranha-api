"""
Unit tests - store layer.
No HTTP. Each test class manages its own isolated tmp dir.
"""

import importlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from helpers import make_record, make_scan_result


def _write_json(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


class TestRecordsStore:
    def setup_method(self):
        self._tmp = tempfile.mkdtemp()
        os.environ["PIRANHA_RECORDS_DIR"] = self._tmp
        import config
        importlib.reload(config)
        import store.records_store as rs
        importlib.reload(rs)
        self._rs = rs

    def teardown_method(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, n: int, **overrides) -> dict:
        r = make_record(n, **overrides)
        _write_json(Path(self._tmp) / f"{r['ave_id']}.json", r)
        return r

    def test_load_from_empty_dir(self):
        assert self._rs._load_from_disk() == {}

    def test_load_single_record(self):
        self._write(1)
        assert "AVE-2026-00001" in self._rs._load_from_disk()

    def test_load_multiple_records(self):
        for i in range(1, 6):
            self._write(i)
        assert len(self._rs._load_from_disk()) == 5

    def test_get_one_existing(self):
        self._write(1)
        self._rs.reload()
        assert self._rs.get_one("AVE-2026-00001") is not None

    def test_get_one_case_insensitive(self):
        self._write(1)
        self._rs.reload()
        assert self._rs.get_one("ave-2026-00001") is not None
        assert self._rs.get_one("AVE-2026-00001") is not None

    def test_get_one_missing_returns_none(self):
        self._rs.reload()
        assert self._rs.get_one("AVE-2026-99999") is None

    def test_count(self):
        for i in range(1, 4):
            self._write(i)
        self._rs.reload()
        assert self._rs.count() == 3

    def test_reload_picks_up_new_file(self):
        self._write(1)
        self._rs.reload()
        assert self._rs.count() == 1
        self._write(2)
        self._rs.reload()
        assert self._rs.count() == 2

    def test_severity_from_cvss(self):
        sev = self._rs.severity_from_cvss
        assert sev(9.5)  == "CRITICAL"
        assert sev(9.0)  == "CRITICAL"
        assert sev(8.9)  == "HIGH"
        assert sev(7.0)  == "HIGH"
        assert sev(6.9)  == "MEDIUM"
        assert sev(4.0)  == "MEDIUM"
        assert sev(3.9)  == "LOW"
        assert sev(0.0)  == "LOW"

    def test_to_summary_fields(self):
        r = make_record(1)
        s = self._rs.to_summary(r)
        for field in ("ave_id", "title", "aivss_score", "severity",
                      "component_type", "status", "piranha_url"):
            assert field in s, f"missing: {field}"
        assert "AVE-2026-00001" in s["piranha_url"]

    def test_to_summary_aivss_fallback(self):
        r = make_record(1)
        del r["aivss_score"]
        r["cvss_ai_score"] = 8.0
        s = self._rs.to_summary(r)
        assert s["aivss_score"] == 8.0
        assert s["severity"]    == "HIGH"

    def test_skips_invalid_json(self):
        bad = Path(self._tmp) / "AVE-2026-00099.json"
        bad.write_text("not valid json", encoding="utf-8")
        assert "AVE-2026-00099" not in self._rs._load_from_disk()

    def test_skips_non_ave_files(self):
        (Path(self._tmp) / "README.md").write_text("hello", encoding="utf-8")
        (Path(self._tmp) / "schema.json").write_text("{}", encoding="utf-8")
        assert self._rs._load_from_disk() == {}


class TestScanStore:
    def setup_method(self):
        self._tmp = tempfile.mkdtemp()
        os.environ["PIRANHA_SCANS_DIR"] = self._tmp
        import config
        importlib.reload(config)
        import store.scan_store as ss
        importlib.reload(ss)
        self._ss = ss

    def teardown_method(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_save_and_get_latest(self):
        self._ss.save_scan("smithery", make_scan_result("smithery"))
        result = self._ss.get_latest("smithery")
        assert result is not None
        assert result["scan_source"]     == "smithery"
        assert result["servers_scanned"] == 100

    def test_get_latest_missing_source_returns_none(self):
        assert self._ss.get_latest("nonexistent-source") is None

    def test_get_history_order(self):
        # Patch _timestamp to return unique, ordered values regardless of
        # the actual timestamp resolution in the deployed scan_store.
        import store.scan_store as ss
        counter = [0]

        def fake_ts():
            counter[0] += 1
            return f"2026-05-17T08:00:{counter[0]:02d}.000000"

        with patch.object(ss, "_timestamp", side_effect=fake_ts):
            for i in range(3):
                ss.save_scan("smithery",
                    {**make_scan_result("smithery"), "servers_scanned": 100 + i})

        history = self._ss.get_history("smithery", limit=3)
        assert len(history) == 3
        # newest first (highest timestamp = last saved = servers_scanned 102)
        assert history[0]["servers_scanned"] == 102

    def test_get_history_respects_limit(self):
        import store.scan_store as ss
        counter = [0]

        def fake_ts():
            counter[0] += 1
            return f"2026-05-17T08:00:{counter[0]:02d}.000000"

        with patch.object(ss, "_timestamp", side_effect=fake_ts):
            for _ in range(5):
                ss.save_scan("smithery", make_scan_result("smithery"))

        assert len(self._ss.get_history("smithery", limit=2)) == 2

    def test_history_empty_source_returns_empty_list(self):
        assert self._ss.get_history("no-such-source") == []

    def test_save_submission_returns_id(self):
        sid = self._ss.save_submission("content", {"source": "test", "scan_result": {}})
        assert isinstance(sid, str) and len(sid) == 12 and sid.isalnum()

    def test_get_submission_roundtrip(self):
        sid = self._ss.save_submission("content", {"source": "url", "scan_result": {}})
        result = self._ss.get_submission(sid)
        assert result is not None
        assert result["submission_id"] == sid

    def test_get_submission_missing_returns_none(self):
        assert self._ss.get_submission("000000000000") is None

    def test_source_key_sanitisation(self):
        self._ss.save_scan("../../../etc/passwd", make_scan_result())
        scans_root = Path(self._tmp)
        for p in scans_root.rglob("*.json"):
            assert scans_root in p.parents

    def test_atomic_write_no_partial_files(self):
        self._ss.save_scan("smithery", make_scan_result())
        assert list(Path(self._tmp).rglob("*.tmp")) == []


class TestOwaspMcpMap:
    def test_known_mapping(self):
        from store.owasp_mcp_map import get_owasp_mcp
        result = get_owasp_mcp("AVE-2026-00001")
        assert isinstance(result, list) and len(result) > 0
        assert all(m.startswith("MCP") for m in result)

    def test_unknown_id_returns_empty(self):
        from store.owasp_mcp_map import get_owasp_mcp
        assert get_owasp_mcp("AVE-2026-99999") == []

    def test_none_returns_empty(self):
        from store.owasp_mcp_map import get_owasp_mcp
        assert get_owasp_mcp(None) == []

    def test_all_48_records_covered(self):
        from store.owasp_mcp_map import AVE_TO_OWASP_MCP
        assert len(AVE_TO_OWASP_MCP) == 48

    def test_all_categories_valid_format(self):
        from store.owasp_mcp_map import AVE_TO_OWASP_MCP
        for ave_id, cats in AVE_TO_OWASP_MCP.items():
            for cat in cats:
                assert cat.startswith("MCP") and cat[3:].isdigit(), \
                    f"{ave_id}: bad category {cat}"


class TestCacheNoOp:
    def setup_method(self):
        os.environ.pop("REDIS_URL", None)

    def test_get_returns_none_without_redis(self):
        from store.cache import cache_get
        assert cache_get("any:key") is None

    def test_set_is_silent_without_redis(self):
        from store.cache import cache_set
        cache_set("any:key", {"data": 1})

    def test_delete_is_silent_without_redis(self):
        from store.cache import cache_delete
        cache_delete("any:key")

    def test_flush_returns_zero_without_redis(self):
        from store.cache import cache_flush
        assert cache_flush() == 0

    def test_cache_info_reports_disabled(self):
        from store.cache import cache_info
        assert cache_info()["connected"] is False
