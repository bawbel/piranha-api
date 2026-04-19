# PiranhaDB API

Behavioral threat intelligence database for agentic AI vulnerabilities.
Serves the [AVE standard](https://github.com/bawbel/bawbel-ave) records via REST API.

## Run locally

```bash
pip install fastapi "uvicorn[standard]"
PIRANHA_RECORDS_DIR=./records uvicorn main:app --reload
```

API available at `http://localhost:8000`
Interactive docs at `http://localhost:8000/docs`

## Docker

```bash
docker build -t piranha-api .
docker run -p 8000:8000 piranha-api
```

## Deploy to Railway / Render / Fly.io

Point `PIRANHA_RECORDS_DIR` to your records directory.
Set `PIRANHA_ENV=production` to enable record caching.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/` | API info and links |
| GET | `/health` | Health check |
| GET | `/ave` | List all records (filter by severity, type, status) |
| GET | `/ave/{ave_id}` | Full record |
| GET | `/ave/{ave_id}/detection` | Detection guidance only |
| GET | `/search?q=<query>` | Search across title, description, attack class |
| GET | `/stats` | Registry statistics |

## Adding records

Drop new `AVE-YYYY-NNNNN.json` files into the `records/` directory.
The API picks them up automatically (no restart needed in dev mode).

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PIRANHA_RECORDS_DIR` | `./records` | Path to AVE record JSON files |
| `PIRANHA_ENV` | — | Set to `production` to cache records in memory |
