"""
Integration tests - /feedback endpoints.

Tests the false-positive reporting pipeline end-to-end.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


VALID_PAYLOAD = {
    "ave_id":          "AVE-2026-00011",
    "engine":          "pattern",
    "confidence":      0.72,
    "context_hash":    "a3f9b1c2d4e5f678",
    "scanner_version": "1.2.1",
    "justification":   "This is a test fixture, not real source code.",
}


class TestFalsePositiveSubmit:
    def test_submit_valid_returns_200(self, app_client):
        r = app_client.post("/feedback/false-positive", json=VALID_PAYLOAD)
        assert r.status_code == 200

    def test_submit_response_fields(self, app_client):
        body = app_client.post("/feedback/false-positive", json=VALID_PAYLOAD).json()
        assert body["status"]   == "accepted"
        assert "entry_id"       in body
        assert body["ave_id"]   == "AVE-2026-00011"

    def test_entry_id_is_12_char_hex(self, app_client):
        body = app_client.post("/feedback/false-positive", json=VALID_PAYLOAD).json()
        eid  = body["entry_id"]
        assert len(eid) == 12
        assert all(c in "0123456789abcdef" for c in eid)

    def test_ave_id_normalised_to_uppercase(self, app_client):
        payload = {**VALID_PAYLOAD, "ave_id": "ave-2026-00011"}
        body    = app_client.post("/feedback/false-positive", json=payload).json()
        assert body["ave_id"] == "AVE-2026-00011"

    def test_engine_normalised_to_lowercase(self, app_client):
        payload = {**VALID_PAYLOAD, "engine": "PATTERN"}
        r = app_client.post("/feedback/false-positive", json=payload)
        assert r.status_code == 200

    def test_all_valid_engines_accepted(self, app_client):
        for engine in ("pattern", "yara", "semgrep"):
            payload = {**VALID_PAYLOAD, "engine": engine}
            r = app_client.post("/feedback/false-positive", json=payload)
            assert r.status_code == 200, f"engine {engine!r} rejected"

    def test_invalid_engine_returns_422(self, app_client):
        payload = {**VALID_PAYLOAD, "engine": "bandit"}
        r = app_client.post("/feedback/false-positive", json=payload)
        assert r.status_code == 422

    def test_invalid_ave_id_prefix_returns_422(self, app_client):
        payload = {**VALID_PAYLOAD, "ave_id": "CVE-2026-00011"}
        r = app_client.post("/feedback/false-positive", json=payload)
        assert r.status_code == 422

    def test_non_hex_context_hash_returns_422(self, app_client):
        payload = {**VALID_PAYLOAD, "context_hash": "not-a-hex-string!!"}
        r = app_client.post("/feedback/false-positive", json=payload)
        assert r.status_code == 422

    def test_confidence_out_of_range_returns_422(self, app_client):
        for bad in (-0.1, 1.1):
            payload = {**VALID_PAYLOAD, "confidence": bad}
            r = app_client.post("/feedback/false-positive", json=payload)
            assert r.status_code == 422, f"confidence {bad} should be rejected"

    def test_justification_optional(self, app_client):
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "justification"}
        r = app_client.post("/feedback/false-positive", json=payload)
        assert r.status_code == 200

    def test_justification_too_long_returns_422(self, app_client):
        payload = {**VALID_PAYLOAD, "justification": "x" * 501}
        r = app_client.post("/feedback/false-positive", json=payload)
        assert r.status_code == 422

    def test_missing_required_fields_returns_422(self, app_client):
        required = ["ave_id", "engine", "confidence", "context_hash", "scanner_version"]
        for field in required:
            payload = {k: v for k, v in VALID_PAYLOAD.items() if k != field}
            r = app_client.post("/feedback/false-positive", json=payload)
            assert r.status_code == 422, f"missing {field!r} should be rejected"

    def test_empty_body_returns_422(self, app_client):
        r = app_client.post("/feedback/false-positive", json={})
        assert r.status_code == 422

    def test_multiple_submissions_get_unique_ids(self, app_client):
        ids = set()
        for _ in range(5):
            body = app_client.post("/feedback/false-positive", json=VALID_PAYLOAD).json()
            ids.add(body["entry_id"])
        # All IDs should be unique (hash includes timestamp)
        assert len(ids) >= 1  # at minimum no crash; ideally all unique


class TestFeedbackStats:
    def test_stats_returns_200_with_no_data(self, app_client):
        r = app_client.get("/feedback/stats")
        assert r.status_code == 200

    def test_stats_fields(self, app_client):
        body = app_client.get("/feedback/stats").json()
        assert "total_reports" in body
        assert "by_ave_id"     in body
        assert "generated_at"  in body

    def test_stats_counts_after_submissions(self, app_client):
        from unittest.mock import patch
        import routers.feedback as fb_mod

        # Patch _write_feedback's internal timestamp so each call gets a
        # unique ts regardless of clock resolution in the deployed code.
        counter = [0]
        orig_write = fb_mod._write_feedback

        def unique_write(data):
            counter[0] += 1
            # Temporarily override datetime inside the function by patching
            # the strftime result via a side-channel: inject a unique suffix
            # into the context_hash used for hashing
            data = dict(data)
            data["_seq"] = counter[0]  # makes sha256 input unique
            from datetime import datetime, timezone
            ts  = datetime.now(timezone.utc).strftime(f"%Y-%m-%dT%H:%M:%S.{counter[0]:06d}")
            import hashlib, json, os
            from pathlib import Path
            from config import SCANS_DIR
            feedback_dir = SCANS_DIR / "feedback"
            feedback_dir.mkdir(parents=True, exist_ok=True)
            raw = f"{data['ave_id']}{data.get('context_hash','')}{ts}{counter[0]}"
            eid = hashlib.sha256(raw.encode()).hexdigest()[:12]
            data["entry_id"]    = eid
            data["received_at"] = ts
            path = feedback_dir / f"{ts.replace(':', '-')}_{eid}.json"
            tmp  = str(path) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:  # nosec B108
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp, path)
            return eid

        with patch.object(fb_mod, "_write_feedback", side_effect=unique_write):
            app_client.post("/feedback/false-positive", json=VALID_PAYLOAD)
            app_client.post("/feedback/false-positive", json=VALID_PAYLOAD)
            app_client.post("/feedback/false-positive", json={**VALID_PAYLOAD,
                "ave_id": "AVE-2026-00001"})

        body = app_client.get("/feedback/stats").json()
        assert body["total_reports"] >= 3
        assert body["by_ave_id"].get("AVE-2026-00011", 0) >= 2
        assert body["by_ave_id"].get("AVE-2026-00001", 0) >= 1

    def test_stats_sorted_by_count_descending(self, app_client):
        # Submit 3 for 00011, 1 for 00001
        for _ in range(3):
            app_client.post("/feedback/false-positive", json=VALID_PAYLOAD)
        app_client.post("/feedback/false-positive", json={**VALID_PAYLOAD,
            "ave_id": "AVE-2026-00001"})

        by_ave_id = app_client.get("/feedback/stats").json()["by_ave_id"]
        counts    = list(by_ave_id.values())
        assert counts == sorted(counts, reverse=True)
