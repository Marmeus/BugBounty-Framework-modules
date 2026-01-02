# Mantra Find Secrets Module - Install mantra from GitHub
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Install mantra
RUN go install github.com/Brosck/mantra@latest

# Final stage - Python with mantra binary
FROM python:3.11-alpine

# Install minimal dependencies
RUN apk add --no-cache curl && \
    pip install --no-cache-dir requests && \
    rm -rf /var/cache/apk/*

# Copy mantra binary from builder
COPY --from=builder /go/bin/mantra /usr/local/bin/

WORKDIR /app
COPY mantra_find_secrets/runner.py /app/runner.py
COPY mantra_find_secrets/issue.py /app/issue.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH=/usr/local/bin:$PATH

# Environment variable for user agent (can be overridden)
ENV MANTRA_USER_AGENT=""

ENTRYPOINT ["python3", "-u", "/app/runner.py"]


