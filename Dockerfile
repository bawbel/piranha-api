FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi "uvicorn[standard]"

COPY main.py sync_records.py ./

# Sync AVE records from bawbel-ave at build time
RUN python sync_records.py || echo "Sync failed — starting with empty records dir"

ENV PIRANHA_ENV=production
ENV PIRANHA_RECORDS_DIR=/app/records

RUN useradd --create-home --uid 1000 piranha \
    && chown -R piranha:piranha /app
USER piranha

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]