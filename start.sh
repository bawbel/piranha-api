#!/bin/sh
# Sync AVE records from bawbel-ave then start the API server.
# Used as the Railway/Render start command so records stay current on every deploy.
set -e

echo "=== Syncing AVE records from bawbel-ave ==="
python sync_records.py || echo "Sync failed — using existing records"

echo ""
echo "=== Starting PiranhaDB API ==="
exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}"