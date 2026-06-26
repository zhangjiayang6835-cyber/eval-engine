# syntax=docker/dockerfile:1
FROM python:3.10-slim-bookworm

# ------------------------------------------------------------------
# System dependencies
# ------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
    ; \
    rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------
# Non-root user
# ------------------------------------------------------------------
RUN groupadd --gid 1000 sandbox && \
    useradd --uid 1000 --gid sandbox --shell /bin/bash --create-home sandbox

# ------------------------------------------------------------------
# Working directory
# ------------------------------------------------------------------
WORKDIR /app
RUN chown sandbox:sandbox /app

# ------------------------------------------------------------------
# Python packages
# ------------------------------------------------------------------
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir pytest

# ------------------------------------------------------------------
# Drop privileges
# ------------------------------------------------------------------
USER sandbox:sandbox

# Default command: validate the environment
CMD ["python", "-c", "import sys; print(f'Python {sys.version}')"]
