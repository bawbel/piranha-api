FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi uvicorn[standard]

COPY main.py .

# Auto-sync AVE records from bawbel-ave at build time
# Records are the canonical source — no need to maintain a copy in this repo
ARG AVE_REPO=https://github.com/bawbel/bawbel-ave.git
RUN git clone --depth=1 --filter=blob:none --sparse "$AVE_REPO" /tmp/bawbel-ave \
    && cd /tmp/bawbel-ave \
    && git sparse-checkout set records \
    && cp -r records/ /app/records/ \
    && rm -rf /tmp/bawbel-ave \
    && echo "Synced $(ls /app/records/AVE-*.json 2>/dev/null | wc -l) AVE records from bawbel-ave"

ENV PIRANHA_ENV=production
ENV PIRANHA_RECORDS_DIR=/app/records

RUN useradd --create-home --uid 1000 piranha && chown -R piranha /app
COPY start.sh .
RUN chmod +x start.sh
USER piranha

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# start.sh syncs records from bawbel-ave then starts uvicorn
CMD ["./start.sh"]