# OSINT Domains Amass Module - Only Amass tool
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Install Amass
RUN go install -v github.com/owasp-amass/amass/v3/...@latest

# Final stage
FROM python:3.11-slim

# Copy Amass binary
COPY --from=builder /go/bin/amass /usr/local/bin/

WORKDIR /app

# Copy shared utility functions
COPY osint_domains_amass/utils_osint.py /app/utils_osint.py

# Copy runner script and make executable
COPY osint_domains_amass/runner.py /app/runner.py

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PATH=/usr/local/bin:$PATH

# Set entrypoint to runner script
ENTRYPOINT ["python3", "/app/runner.py"]

