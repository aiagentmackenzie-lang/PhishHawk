FROM python:3.14-slim AS builder

# Install build tooling for compiled wheel dependencies (yara-python, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[all]"

# --- Runtime ---
FROM python:3.14-slim

RUN groupadd -r phishhawk && useradd -r -g phishhawk -s /bin/bash -m phishhawk

COPY --from=builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=builder /usr/local/bin/phishhawk /usr/local/bin/phishhawk

USER phishhawk
WORKDIR /data

ENTRYPOINT ["phishhawk"]
CMD ["--help"]
