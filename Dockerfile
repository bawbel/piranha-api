FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY config.py main.py sync_records.py ./
COPY routers/ ./routers/
COPY store/   ./store/

# Create data directories
# Mount a Railway volume at /app/scans for scan result persistence
# Mount a Railway volume at /app/records for AVE records (or sync on startup)
RUN mkdir -p /app/records /app/scans

# Non-root user for security
RUN useradd --create-home --uid 1000 piranha \
    && chown -R piranha:piranha /app
USER piranha

ENV PIRANHA_ENV=production
ENV PIRANHA_RECORDS_DIR=/app/records
ENV PIRANHA_SCANS_DIR=/app/scans

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Sync AVE records from bawbel-ave on startup, then start server
CMD ["sh", "-c", "python sync_records.py && uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
