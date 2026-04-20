# PiranhaDB API

Behavioral threat intelligence database for agentic AI vulnerabilities.
Serves the [AVE standard](https://github.com/bawbel/bawbel-ave) records via REST API.

**Live at:** `https://api.piranha.bawbel.io`

[![Records](https://img.shields.io/badge/AVE_Records-8-blue.svg)](https://github.com/bawbel/bawbel-ave/tree/main/records)
[![Status](https://img.shields.io/badge/Status-Live-brightgreen.svg)](https://api.piranha.bawbel.io/health)
[![License](https://img.shields.io/badge/License-Apache_2.0-teal.svg)](LICENSE)

---

## Quick start

No authentication required. Free for all read operations.

```bash
# Health check
curl https://api.piranha.bawbel.io/health

# List all records
curl https://api.piranha.bawbel.io/ave

# Get a specific record
curl https://api.piranha.bawbel.io/ave/AVE-2026-00001

# Detection guidance only
curl https://api.piranha.bawbel.io/ave/AVE-2026-00001/detection

# Search
curl "https://api.piranha.bawbel.io/search?q=injection"

# Filter by severity
curl "https://api.piranha.bawbel.io/ave?severity=CRITICAL"

# Stats
curl https://api.piranha.bawbel.io/stats
```

Interactive docs: [api.piranha.bawbel.io/docs](https://api.piranha.bawbel.io/docs)

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/` | API info and links |
| GET | `/health` | Health check — `{"status":"ok","records":8}` |
| GET | `/ave` | List all records (filter by `severity`, `component_type`, `status`) |
| GET | `/ave/{ave_id}` | Full record including behavioral fingerprint and IOCs |
| GET | `/ave/{ave_id}/detection` | Detection guidance, scan command, IOCs |
| GET | `/search?q={query}` | Scored full-text search |
| GET | `/stats` | Total records, mutation counts, breakdown by severity and attack class |

---

## Enrich bawbel-scanner findings

Every bawbel-scanner finding includes an `ave_id`. Use it to pull the full record:

```python
import requests
from scanner import scan

result = scan("./my-skill.md")

for f in result.findings:
    if f.ave_id:
        record = requests.get(
            f"https://api.piranha.bawbel.io/ave/{f.ave_id}"
        ).json()
        print(f"[{f.severity.value}] {f.title}")
        print(f"  Fingerprint: {record['behavioral_fingerprint']}")
        print(f"  Remediation: {record['remediation']}")
```

---

## Run locally

```bash
pip install fastapi "uvicorn[standard]"
PIRANHA_RECORDS_DIR=./records uvicorn main:app --reload
```

API at `http://localhost:8000` · Swagger UI at `http://localhost:8000/docs`

## Docker

```bash
docker build -t piranha-api .
docker run -p 8000:8000 piranha-api
```

---

## Adding records

The canonical source is [bawbel/bawbel-ave](https://github.com/bawbel/bawbel-ave).
Records sync automatically from that repo on every deploy via `sync_records.py`.

To sync manually:
```bash
python sync_records.py
```

To add a new record: open a PR to `bawbel/bawbel-ave` — it will appear in the API on the next deploy.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PIRANHA_RECORDS_DIR` | `./records` | Path to AVE record JSON files |
| `PIRANHA_ENV` | — | Set to `production` to cache records in memory |

---

## Related

- [bawbel-scanner](https://github.com/bawbel/bawbel-scanner) — `pip install bawbel-scanner`
- [bawbel-ave](https://github.com/bawbel/bawbel-ave) — AVE standard and records
- [bawbel.io/docs](https://bawbel.io/docs) — full documentation

---

Maintained by [Bawbel](https://bawbel.io) · [@bawbel_io](https://twitter.com/bawbel_io)
