#!/bin/sh
# Sync AVE records from bawbel-ave then start the API server.
# Used as the Railway/Render/Docker start command so records stay
# current on every deploy — no image rebuild needed when records change.
set -e

echo "=== Syncing AVE records from bawbel-ave ==="
python sync_records.py || echo "[start] Sync failed — continuing with bundled records"

echo ""
echo "=== Starting PiranhaDB API ==="
exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}"