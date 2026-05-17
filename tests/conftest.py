"""
PiranhaDB - shared pytest fixtures.
"""

import importlib
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from helpers import make_record, make_scan_result  # noqa: E402


# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_dirs(tmp_path):
    records_dir = tmp_path / "records"
    scans_dir   = tmp_path / "scans"
    records_dir.mkdir()
    scans_dir.mkdir()
    return records_dir, scans_dir


@pytest.fixture()
def records_dir_with_data(tmp_dirs):
    records_dir, _ = tmp_dirs

    records = [
        make_record(1, aivss_score=9.4, aivss={"cvss_base": 9.0, "aars": 1.04,
            "thm": 1.0, "mitigation_factor": 1.0,
            "aivss_severity": "CRITICAL", "spec_version": "0.8"},
            attack_class="Metamorphic Payload", component_type="skill"),
        make_record(2, aivss_score=7.8, aivss={"cvss_base": 7.5, "aars": 1.04,
            "thm": 1.0, "mitigation_factor": 1.0,
            "aivss_severity": "HIGH", "spec_version": "0.8"},
            attack_class="Tool Poisoning", component_type="mcp_server"),
        make_record(3, aivss_score=5.0, aivss={"cvss_base": 4.8, "aars": 1.04,
            "thm": 1.0, "mitigation_factor": 1.0,
            "aivss_severity": "MEDIUM", "spec_version": "0.8"},
            attack_class="Data Exfiltration", component_type="skill",
            status="deprecated"),
    ]

    for r in records:
        path = records_dir / f"{r['ave_id']}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)

    return records_dir


@pytest.fixture()
def app_client(records_dir_with_data, tmp_dirs):
    _, scans_dir = tmp_dirs

    os.environ["PIRANHA_RECORDS_DIR"] = str(records_dir_with_data)
    os.environ["PIRANHA_SCANS_DIR"]   = str(scans_dir)
    os.environ["PIRANHA_ENV"]         = "development"

    _reload_all()

    from main import app
    client = TestClient(app, raise_server_exceptions=True)
    yield client

    os.environ.pop("PIRANHA_RECORDS_DIR", None)
    os.environ.pop("PIRANHA_SCANS_DIR",   None)


def _reload_all():
    for mod in [
        "config", "store.cache", "store.records_store", "store.scan_store",
        "store.owasp_mcp_map", "store",
        "routers.records", "routers.registry_scan", "routers.github_scan",
        "routers.stats", "routers.submit", "routers.feedback", "main",
    ]:
        if mod in sys.modules:
            importlib.reload(sys.modules[mod])
