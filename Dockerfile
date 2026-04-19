FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn[standard]

COPY main.py .
COPY records/ ./records/

ENV PIRANHA_ENV=production
ENV PIRANHA_RECORDS_DIR=/app/records

RUN useradd --create-home --uid 1000 piranha && chown -R piranha /app
USER piranha

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
