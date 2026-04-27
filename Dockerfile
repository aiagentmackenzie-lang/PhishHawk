FROM python:3.14-slim AS builder

WORKDIR /build
COPY . .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# --- Runtime ---
FROM python:3.14-slim

RUN groupadd -r phishhawk && useradd -r -g phishhawk -s /bin/bash phishhawk

COPY --from=builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=builder /usr/local/bin/phishhawk /usr/local/bin/phishhawk

USER phishhawk
WORKDIR /data

ENTRYPOINT ["phishhawk"]
CMD ["--help"]