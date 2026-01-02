# OSINT URLs GAU Module - gau only (passive URL gathering)
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Install gau
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest

# Final stage - Alpine is smaller but verify gau works
FROM python:3.11-alpine

# Install minimal dependencies
RUN apk add --no-cache curl && \
    pip install --no-cache-dir requests uro && \
    rm -rf /var/cache/apk/*

COPY --from=builder /go/bin/gau /usr/local/bin/
WORKDIR /app
COPY osint_urls_gau/runner.py /app/runner.py
COPY osint_urls_gau/utils_osint.py /app/utils_osint.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH=/usr/local/bin:$PATH

ENTRYPOINT ["python3", "-u", "/app/runner.py"]

