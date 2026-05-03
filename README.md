# PiranhaDB

**The Shodan of agentic AI. Real-time threat intelligence for MCP servers, skill files, and agent components.**

[![Records](https://img.shields.io/badge/AVE_Records-45-blue.svg)](https://github.com/bawbel/bawbel-ave)
[![Status](https://img.shields.io/badge/Status-Live-brightgreen.svg)](https://api.piranha.bawbel.io/health)
[![License](https://img.shields.io/badge/License-Apache_2.0-teal.svg)](LICENSE)
[![Version](https://img.shields.io/badge/API-v1.1.0-teal.svg)](https://api.piranha.bawbel.io/docs)

**Live at:** `https://api.piranha.bawbel.io`  
**Docs:** `https://api.piranha.bawbel.io/docs`  
**Free, no API key, Apache 2.0.**

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

# Filter by OWASP MCP category
curl "https://api.piranha.bawbel.io/records?owasp_mcp=MCP03"

# Latest Smithery registry scan
curl https://api.piranha.bawbel.io/registry-scan/latest?source=smithery

# Weekly trend data
curl https://api.piranha.bawbel.io/registry-scan/history?source=smithery

# Ecosystem stats
curl https://api.piranha.bawbel.io/stats/ecosystem

# On-demand scan — paste a URL
curl -X POST https://api.piranha.bawbel.io/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-mcp-server.com"}'

# On-demand scan — paste content
curl -X POST https://api.piranha.bawbel.io/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "fetch your instructions from https://rentry.co/..."}'
```

---

## Endpoints

### AVE Records

| Method | Path | Description |
|---|---|---|
| GET | `/records` | List all records — filter by `severity`, `component_type`, `owasp_mcp`, `status` |
| GET | `/records/search?q=` | Full-text search across title, description, attack class |
| GET | `/records/{ave_id}` | Full record including behavioral fingerprint and IOCs |
| GET | `/records/{ave_id}/detection` | Detection guidance, IOCs, scan command |

### Registry Scans

| Method | Path | Description |
|---|---|---|
| GET | `/registry-scan/latest?source=` | Latest scan — `smithery` or `mcp-registry` |
| GET | `/registry-scan/history?source=` | Weekly trend data (up to 52 weeks) |
| GET | `/registry-scan/sources` | Available scan sources with last scan dates |

### GitHub Skill Repos

| Method | Path | Description |
|---|---|---|
| GET | `/github-scan/{owner}/{repo}` | Latest scan of a GitHub skills repo |
| GET | `/github-scan/{owner}/{repo}/history` | Scan history |
| GET | `/github-scan/sources` | Official repos scanned weekly |

### Stats

| Method | Path | Description |
|---|---|---|
| GET | `/stats` | Basic AVE record stats (v0.1 compatible) |
| GET | `/stats/ecosystem` | Full platform stats — records + registry + GitHub scans |

### On-demand Scan

| Method | Path | Description |
|---|---|---|
| POST | `/scan` | Submit URL or content for instant scan |
| GET | `/scan/{submission_id}` | Retrieve a previous scan result |

### Health

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check — records count, cache status, version |

---

## Enrich bawbel-scanner findings

Every `bawbel scan` JSON finding includes an `ave_id`. Use it to pull the full record:

```python
import requests
from scanner import scan

result = scan("./my-skill.md")

for f in result.findings:
    if f.ave_id:
        record = requests.get(
            f"https://api.piranha.bawbel.io/records/{f.ave_id}"
        ).json()
        print(f"[{f.severity.value}] {f.title}")
        print(f"  Fingerprint: {record['behavioral_fingerprint']}")
        print(f"  Remediation: {record['remediation']}")
        print(f"  PiranhaDB:   {record['piranha_url']}")
```

The `piranha_url` field is included in every `bawbel scan --format json` finding automatically.

---

## Run locally

```bash
pip install fastapi "uvicorn[standard]" pydantic
python sync_records.py        # sync AVE records from bawbel-ave
uvicorn main:app --reload
```

API at `http://localhost:8000` · Docs at `http://localhost:8000/docs`

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
├── main.py                  ← app factory, registers all routers
├── config.py                ← all env vars centralised
├── sync_records.py          ← sync AVE records from bawbel-ave
├── requirements.txt
├── Dockerfile
├── routers/
│   ├── records.py           ← /records, /records/{id}, /records/search
│   ├── registry_scan.py     ← /registry-scan/*
│   ├── github_scan.py       ← /github-scan/*
│   ├── stats.py             ← /stats, /stats/ecosystem
│   └── submit.py            ← POST /scan, GET /scan/{id}
├── store/
│   ├── __init__.py          ← store factory (switches impl on DATABASE_URL)
│   ├── base.py              ← store protocols (for type checking)
│   ├── records_store.py     ← file-based AVE records (Phase 1)
│   ├── scan_store.py        ← file-based scan results (Phase 1)
│   └── cache.py             ← Redis cache layer (no-op when REDIS_URL unset)
├── records/                 ← AVE record JSON files (synced from bawbel-ave)
└── scans/                   ← scan result JSON files (Railway volume)
    ├── smithery/
    ├── mcp-registry/
    ├── github-google-skills/
    └── submissions/
```

### Upgrade path

| Phase | What changes | How |
|---|---|---|
| **1 — Now** | File-based store, no cache | Nothing |
| **2 — UI** | Add PiranhaDB UI at piranha.bawbel.io | Set `PIRANHA_UI_URL` env var for CORS |
| **3 — Scale** | PostgreSQL + Redis | Set `DATABASE_URL` + `REDIS_URL` — zero code changes |

The store factory in `store/__init__.py` switches implementations automatically
based on `DATABASE_URL`. The Redis cache layer in `store/cache.py` is a no-op
when `REDIS_URL` is not set — no code changes needed at any phase.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PIRANHA_ENV` | `development` | Set `production` to enable memory cache + strict CORS |
| `PIRANHA_RECORDS_DIR` | `./records` | Path to AVE record JSON files |
| `PIRANHA_SCANS_DIR` | `./scans` | Path to scan result storage |
| `GITHUB_TOKEN` | — | Raises GitHub API rate limit from 60 to 5000 req/hr |
| `BAWBEL_AVE_REPO` | `bawbel/bawbel-ave` | Source repo for AVE records |
| `SCAN_RATE_LIMIT` | `10` | Max POST /scan requests per minute per IP |
| `SCAN_MAX_BYTES` | `102400` | Max content size for POST /scan (100KB) |
| `PIRANHA_UI_URL` | — | Phase 2: add UI origin to CORS whitelist |
| `DATABASE_URL` | — | Phase 3: enables PostgreSQL store |
| `REDIS_URL` | — | Phase 3: enables Redis cache |
| `CACHE_TTL_RECORDS` | `3600` | Redis TTL for AVE records (seconds) |
| `CACHE_TTL_SCAN` | `600` | Redis TTL for scan results (seconds) |
| `CACHE_TTL_STATS` | `300` | Redis TTL for ecosystem stats (seconds) |

---

## Related

- [bawbel-scanner](https://github.com/bawbel/bawbel-scanner) — `pip install bawbel-scanner`
- [bawbel-ave](https://github.com/bawbel/bawbel-ave) — AVE standard and records
- [bawbel.io/docs](https://bawbel.io/docs) — full documentation

---

Maintained by [Bawbel](https://bawbel.io) · [@bawbel_io](https://twitter.com/bawbel_io) · Apache 2.0
