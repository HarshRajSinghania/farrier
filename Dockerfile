# syntax=docker/dockerfile:1
# Farrier engine + API. Data (SQLite, sealed keys, master.key, change packs) lives in /data.
# Mirrors and regulated builds: pin by digest, e.g. python:3.15-slim@sha256:<digest>.
FROM python:3.15-slim

# Database drivers baked in, so FARRIER_DATABASE_URL=postgresql://... works out of the box
# (the cloud reference deployments in deploy/terraform all use PostgreSQL).
ARG FARRIER_EXTRAS=postgres

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FARRIER_DATA=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY farrier ./farrier
# /var/lib/farrier/objects is the default FARRIER_STORAGE_URL (file://) and must be writable as 10001.
RUN pip install --no-cache-dir ".[${FARRIER_EXTRAS}]" \
 && useradd --system --uid 10001 farrier \
 && mkdir -p /data /var/lib/farrier/objects \
 && chown farrier /data /var/lib/farrier /var/lib/farrier/objects

USER 10001
VOLUME ["/data"]
EXPOSE 8740
# FARRIER_API_TOKEN is required: serve refuses a non-loopback bind without it.
CMD ["farrier", "serve", "--host", "0.0.0.0", "--port", "8740"]

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8740/healthz')" || exit 1
