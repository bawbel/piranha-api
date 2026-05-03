"""
Sync AVE records from bawbel-ave repository.

Run this script at deploy time to keep piranha-api in sync with the canonical
AVE records in github.com/bawbel/bawbel-ave.

Usage:
    python sync_records.py

Environment:
    AVE_REPO_URL   — override the source repo API URL
    RECORDS_DIR    — override target directory (default: ./records)
    GITHUB_TOKEN   — optional personal access token (raises rate limit 60 → 5000 req/hr)
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

AVE_REPO_API = os.environ.get(
    "AVE_REPO_URL",
    "https://api.github.com/repos/bawbel/bawbel-ave/contents/records"
)
RECORDS_DIR  = Path(os.environ.get("RECORDS_DIR", "./records"))
RAW_BASE     = "https://raw.githubusercontent.com/bawbel/bawbel-ave/main/records"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def _headers() -> dict:
    h = {"User-Agent": "piranha-api/sync"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def fetch_json(url: str) -> dict | list:
    req = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def sync() -> int:
    """Sync records from GitHub. Returns count of records synced."""
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[sync] Fetching record list from GitHub...")
    try:
        contents = fetch_json(AVE_REPO_API)
    except Exception as e:
        print(f"[sync] ERROR fetching record list: {e}", file=sys.stderr)
        existing = len(list(RECORDS_DIR.glob("AVE-*.json")))
        print(f"[sync] Using {existing} existing bundled records", file=sys.stderr)
        return 0

    ave_files = sorted(
        item["name"] for item in contents
        if isinstance(item, dict)
        and item.get("name", "").startswith("AVE-")
        and item.get("name", "").endswith(".json")
    )

    if not ave_files:
        print("[sync] WARNING: no AVE JSON files found in repo", file=sys.stderr)
        return 0

    print(f"[sync] {len(ave_files)} records found in bawbel-ave repo")

    synced = 0
    errors = 0

    for filename in ave_files:
        url  = f"{RAW_BASE}/{filename}"
        dest = RECORDS_DIR / filename
        try:
            record = fetch_json(url)
            if not record.get("ave_id"):
                raise ValueError("missing ave_id field")
            with open(dest, "w") as f:
                json.dump(record, f, indent=2)
            print(f"[sync]   ✓ {filename}  ({record.get('attack_class', '')[:45]})")
            synced += 1
        except Exception as e:
            errors += 1
            print(f"[sync]   ✗ {filename}: {e}", file=sys.stderr)
            if dest.exists():
                print(f"[sync]     keeping existing cached copy", file=sys.stderr)

    # Remove stale local records no longer in the repo
    for local in RECORDS_DIR.glob("AVE-*.json"):
        if local.name not in ave_files:
            local.unlink()
            print(f"[sync]   - removed stale {local.name}")

    print(f"[sync] Complete: {synced} synced, {errors} errors → {RECORDS_DIR}")
    return synced


if __name__ == "__main__":
    count = sync()
    sys.exit(0 if count > 0 else 1)