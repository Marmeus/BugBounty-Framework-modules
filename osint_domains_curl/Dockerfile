# OSINT Domains Curl Module - curl and jq based OSINT
FROM python:3.11-slim

# Install curl and jq
RUN apt-get update && \
    apt-get install -y curl jq && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy shared utility functions
COPY osint_domains_curl/utils_osint.py /app/utils_osint.py

# Copy runner script and make executable
COPY osint_domains_curl/runner.py /app/runner.py

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PATH=/usr/local/bin:$PATH

# Set entrypoint to runner script
ENTRYPOINT ["python3", "/app/runner.py"]

