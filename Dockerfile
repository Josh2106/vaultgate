# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Stage 1: build a self-contained virtualenv from the hash-pinned lock file.
# ---------------------------------------------------------------------------
FROM python:3.15.1-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.lock .
RUN pip install --require-hashes -r requirements.lock

COPY pyproject.toml README.md LICENSE ./
COPY app ./app
RUN pip install --no-deps . && python -m compileall -q /opt/venv

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime. No build tools, no pip cache, non-root, read-only FS.
# ---------------------------------------------------------------------------
FROM python:3.15.1-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="vaultgate" \
      org.opencontainers.image.description="Multi-tenant secrets & API-key management API" \
      org.opencontainers.image.source="https://github.com/Josh2106/vaultgate" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VG_ENVIRONMENT=production

# Pull in Debian security updates for the base image (fixes CVEs flagged by Trivy)
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 vaultgate \
 && useradd --system --uid 10001 --gid vaultgate --home-dir /nonexistent \
      --shell /usr/sbin/nologin vaultgate \
 && mkdir -p /keys && chown 10001:10001 /keys   # mount point for key material

COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv
COPY alembic.ini ./
COPY migrations ./migrations

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

# --timeout-graceful-shutdown lets in-flight requests finish on SIGTERM; the
# Kubernetes preStop hook + readiness flip drain traffic before that.
CMD ["uvicorn", "app.main:app_factory", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", \
     "--no-server-header", "--no-access-log", \
     "--timeout-graceful-shutdown", "20"]
