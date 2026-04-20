"""
Sync AVE records from bawbel-ave repository.

Run this script at deploy time to keep piranha-api in sync with the canonical
AVE records in github.com/bawbel/bawbel-ave.

Usage:
    python sync_records.py

Environment:
    AVE_REPO_URL  — override the source repo (default: bawbel/bawbel-ave raw URL)
    RECORDS_DIR   — override target directory (default: ./records)
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
RECORDS_DIR = Path(os.environ.get("RECORDS_DIR", "./records"))
RAW_BASE    = "https://raw.githubusercontent.com/bawbel/bawbel-ave/main/records"


def fetch_json(url: str) -> dict | list:
    req = urllib.request.Request(url, headers={"User-Agent": "piranha-api/sync"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def sync() -> int:
    """Sync records. Returns count of records synced."""
    RECORDS_DIR.mkdir(exist_ok=True)

    print(f"Fetching record list from {AVE_REPO_API}...")
    try:
        contents = fetch_json(AVE_REPO_API)
    except Exception as e:
        print(f"ERROR fetching record list: {e}", file=sys.stderr)
        return 0

    ave_files = [
        item["name"] for item in contents
        if item["name"].startswith("AVE-") and item["name"].endswith(".json")
    ]

    synced = 0
    for filename in sorted(ave_files):
        url = f"{RAW_BASE}/{filename}"
        try:
            record = fetch_json(url)
            dest   = RECORDS_DIR / filename
            with open(dest, "w") as f:
                json.dump(record, f, indent=2)
            print(f"  ✓ {filename}")
            synced += 1
        except Exception as e:
            print(f"  ✗ {filename}: {e}", file=sys.stderr)

    print(f"\nSynced {synced}/{len(ave_files)} records → {RECORDS_DIR}")
    return synced


if __name__ == "__main__":
    count = sync()
    sys.exit(0 if count > 0 else 1)