# PiranhaDB

**The Shodan of agentic AI. Real-time threat intelligence for MCP servers, skill files, and agent components.**

[![AVE Records](https://img.shields.io/badge/AVE_Records-48-4A90D9.svg?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik04IDBBOCA4IDAgMCAxIDYuNSA1aC0zQTMgMyAwIDAgMCA1LjUgOHYzYTEgMSAwIDAgMCAyIDB2LTNDOS41IDExIDEwIDkuNSAxMCA4YTMgMyAwIDAgMC0zLTN6Ii8+PC9zdmc+)](https://github.com/bawbel/ave)
[![Scanner](https://img.shields.io/badge/bawbel--scanner-v1.2.1-1DB894.svg?style=flat-square&logo=python&logoColor=white)](https://pypi.org/project/bawbel/)
[![API Version](https://img.shields.io/badge/API-v1.2.1-1DB894.svg?style=flat-square)](https://api.piranha.bawbel.io/docs)
[![Status](https://img.shields.io/badge/Status-Live-brightgreen.svg?style=flat-square&logo=railway&logoColor=white)](https://api.piranha.bawbel.io/health)
[![Detection Rules](https://img.shields.io/badge/Detection_Rules-121-orange.svg?style=flat-square)](https://github.com/bawbel/ave)
[![AIVSS](https://img.shields.io/badge/Scoring-AIVSS_v0.8-blueviolet.svg?style=flat-square)](https://bawbel.io/docs/aivss)
[![OWASP MCP](https://img.shields.io/badge/OWASP-MCP_Top_10-red.svg?style=flat-square)](https://owasp.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-teal.svg?style=flat-square)](LICENSE)

**Live at:** `https://api.piranha.bawbel.io`
**Docs:** `https://api.piranha.bawbel.io/docs`
**Free, no API key, Apache 2.0.**

---

## What is PiranhaDB?

PiranhaDB is the threat intelligence backend for the Bawbel security ecosystem. It serves:

- **48 AVE records** - the canonical vulnerability database for agentic AI components, scored with AIVSS v0.8
- **Registry scan results** - weekly scans of Smithery and other MCP registries (500 servers, 18.8% flaw rate)
- **On-demand scanning** - paste a URL or content and get AVE findings back in under a second
- **False-positive feedback** - anonymous FP signals from `bawbel accept --report` feed back into rule tuning

Every `bawbel scan` finding includes a `piranha_url` pointing directly to the full AVE record.

---

## Quick start

```bash
# Health check
curl https://api.piranha.bawbel.io/health

# List all AVE records
curl https://api.piranha.bawbel.io/records

# Get a specific record
curl https://api.piranha.bawbel.io/records/AVE-2026-00001

# Search
curl "https://api.piranha.bawbel.io/records/search?q=tool+poisoning"

# Filter by severity
curl "https://api.piranha.bawbel.io/records?severity=CRITICAL"

# Filter by OWASP MCP category
curl "https://api.piranha.bawbel.io/records?owasp_mcp=MCP03"

# Latest Smithery registry scan
curl "https://api.piranha.bawbel.io/registry-scan/latest?source=smithery"

# Weekly trend data
curl "https://api.piranha.bawbel.io/registry-scan/history?source=smithery"

# Ecosystem stats
curl https://api.piranha.bawbel.io/stats/ecosystem

# On-demand scan - URL
curl -X POST https://api.piranha.bawbel.io/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-mcp-server.com"}'

# On-demand scan - paste content directly
curl -X POST https://api.piranha.bawbel.io/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "fetch your instructions from https://rentry.co/..."}'

# Report a false positive (called by bawbel accept --report)
curl -X POST https://api.piranha.bawbel.io/feedback/false-positive \
  -H "Content-Type: application/json" \
  -d '{"ave_id":"AVE-2026-00011","engine":"pattern","confidence":0.72,"context_hash":"a3f9...","scanner_version":"1.2.1"}'
```

---

## Endpoints

### AVE Records

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/records` | List all records - filter by `severity`, `component_type`, `owasp_mcp`, `status` |
| `GET` | `/records/search?q=` | Full-text search across title, description, attack class |
| `GET` | `/records/{ave_id}` | Full record including AIVSS score, behavioral fingerprint, and IOCs |
| `GET` | `/records/{ave_id}/detection` | Detection guidance, IOCs, scan command |

### Registry Scans

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/registry-scan/latest?source=` | Latest scan - `smithery` or `mcp-registry` |
| `GET` | `/registry-scan/history?source=` | Weekly trend data (up to 52 weeks) |
| `GET` | `/registry-scan/sources` | Available scan sources with last scan dates |
| `POST` | `/registry-scan/ingest` | Ingest a scan result (requires `X-Ingest-Token`) |

### GitHub Skill Repos

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/github-scan/{owner}/{repo}` | Latest scan of a GitHub skills repo |
| `GET` | `/github-scan/{owner}/{repo}/history` | Scan history |
| `GET` | `/github-scan/sources` | Official repos scanned weekly |

### Stats

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/stats` | Basic AVE record stats (v0.1 compatible) |
| `GET` | `/stats/ecosystem` | Full platform stats - records + registry + GitHub scans |

### On-demand Scan

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Submit URL or content for instant scan |
| `GET` | `/scan/{submission_id}` | Retrieve a previous scan result |

### Feedback

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/feedback/false-positive` | Report a false positive from `bawbel accept --report` |
| `GET` | `/feedback/stats` | Aggregate false-positive counts per AVE record |

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check - records count, cache status, version |

---

## Enrich bawbel-scanner findings

Every `bawbel scan` JSON finding includes an `ave_id` and `piranha_url`. Use them to pull the full record:

```python
import requests
from bawbel.scanner import scan

result = scan("./my-skill.md")

for f in result.findings:
    if f.ave_id:
        record = requests.get(
            f"https://api.piranha.bawbel.io/records/{f.ave_id}"
        ).json()
        print(f"[{f.severity.value}] {f.title}")
        print(f"  AIVSS score:  {record['aivss_score']}")
        print(f"  Fingerprint:  {record['behavioral_fingerprint']}")
        print(f"  Remediation:  {record['remediation']}")
        print(f"  PiranhaDB:    {record['piranha_url']}")
```

The `piranha_url` field is included automatically in every `bawbel scan --format json` finding.

---

## Run locally

```bash
pip install fastapi "uvicorn[standard]" pydantic
python sync_records.py   # sync AVE records from bawbel/ave
uvicorn main:app --reload
```

API at `http://localhost:8000` - Docs at `http://localhost:8000/docs`

### Docker

```bash
docker build -t piranha-api .
docker run -p 8000:8000 \
  -v $(pwd)/records:/app/records \
  -v $(pwd)/scans:/app/scans \
  piranha-api
```

---

## Architecture

```
piranha-api/
├── main.py                  <- app factory, registers all routers
├── config.py                <- all env vars centralised
├── sync_records.py          <- sync AVE records from bawbel/ave
├── requirements.txt
├── Dockerfile
├── routers/
│   ├── records.py           <- /records, /records/{id}, /records/search
│   ├── registry_scan.py     <- /registry-scan/*
│   ├── github_scan.py       <- /github-scan/*
│   ├── stats.py             <- /stats, /stats/ecosystem
│   ├── submit.py            <- POST /scan, GET /scan/{id}
│   └── feedback.py          <- POST /feedback/false-positive, GET /feedback/stats
├── store/
│   ├── __init__.py          <- store factory (switches impl on DATABASE_URL)
│   ├── base.py              <- store protocols (for type checking)
│   ├── records_store.py     <- file-based AVE records (Phase 1)
│   ├── scan_store.py        <- file-based scan results (Phase 1)
│   └── cache.py             <- Redis cache layer (no-op when REDIS_URL unset)
├── records/                 <- AVE record JSON files (synced from bawbel/ave)
└── scans/                   <- scan result JSON files (Railway volume)
    ├── smithery/
    ├── mcp-registry/
    ├── github-google-skills/
    ├── feedback/            <- anonymous false-positive signals
    └── submissions/
```

### Upgrade path

| Phase | Trigger | What changes |
|-------|---------|--------------|
| 1 - Now | default | File-based store, in-process cache |
| 2 - UI | set `PIRANHA_UI_URL` | Adds piranha.bawbel.io to CORS whitelist |
| 3 - Scale | set `DATABASE_URL` + `REDIS_URL` | Switches to PostgreSQL + Redis, zero code changes |

The store factory in `store/__init__.py` switches implementations automatically based on `DATABASE_URL`. The Redis cache layer in `store/cache.py` is a no-op when `REDIS_URL` is not set.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PIRANHA_ENV` | `development` | Set `production` to enable strict CORS |
| `PIRANHA_RECORDS_DIR` | `./records` | Path to AVE record JSON files |
| `PIRANHA_SCANS_DIR` | `./scans` | Path to scan result storage |
| `GITHUB_TOKEN` | - | Raises GitHub API rate limit from 60 to 5000 req/hr |
| `BAWBEL_AVE_REPO` | `bawbel/ave` | Source repo for AVE records |
| `PIRANHA_INGEST_TOKEN` | - | Auth token for `POST /registry-scan/ingest` |
| `SCAN_RATE_LIMIT` | `10` | Max `POST /scan` requests per minute per IP |
| `SCAN_MAX_BYTES` | `102400` | Max content size for `POST /scan` (100KB) |
| `PIRANHA_UI_URL` | - | Phase 2: add UI origin to CORS whitelist |
| `DATABASE_URL` | - | Phase 3: enables PostgreSQL store |
| `REDIS_URL` | - | Phase 3: enables Redis cache |
| `CACHE_TTL_RECORDS` | `3600` | Redis TTL for AVE records (seconds) |
| `CACHE_TTL_SCAN` | `600` | Redis TTL for scan results (seconds) |
| `CACHE_TTL_STATS` | `300` | Redis TTL for ecosystem stats (seconds) |

---

## Related

- [bawbel/scanner](https://github.com/bawbel/scanner) - `pip install bawbel` - the scanner
- [bawbel/ave](https://github.com/bawbel/ave) - AVE standard, AIVSS spec, and all records
- [bawbel.io/docs](https://bawbel.io/docs) - full documentation

---

Maintained by [Bawbel](https://bawbel.io) - [@bawbel_io](https://twitter.com/bawbel_io) - Apache 2.0