FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi "uvicorn[standard]"

# Application code
COPY main.py         .
COPY sync_records.py .
COPY start.sh        .
RUN chmod +x start.sh

# Bundle records as offline fallback only —
# start.sh will overwrite them with the latest from bawbel-ave on every start.
# To skip the git clone at build time set: --build-arg SKIP_CLONE=1
ARG SKIP_CLONE=
RUN if [ -z "$SKIP_CLONE" ]; then \
      apt-get update && apt-get install -y --no-install-recommends git \
      && rm -rf /var/lib/apt/lists/* \
      && git clone --depth=1 --filter=blob:none --sparse \
           https://github.com/bawbel/bawbel-ave.git /tmp/bawbel-ave \
      && cd /tmp/bawbel-ave && git sparse-checkout set records \
      && mkdir -p /app/records \
      && cp /tmp/bawbel-ave/records/AVE-*.json /app/records/ \
      && rm -rf /tmp/bawbel-ave \
      && echo "Bundled $(ls /app/records/AVE-*.json | wc -l) records as fallback"; \
    fi

# Non-root user
RUN useradd --create-home --uid 1000 piranha \
 && mkdir -p /app/records \
 && chown -R piranha /app
USER piranha

ENV PIRANHA_RECORDS_DIR=/app/records

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# start.sh: syncs latest records from bawbel-ave then starts uvicorn
CMD ["./start.sh"]