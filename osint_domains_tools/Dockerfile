# OSINT Domains Tools Module - Subfinder and Assetfinder
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Install Subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Assetfinder
RUN go install -v github.com/tomnomnom/assetfinder@latest

# Final stage
FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y wget
RUN wget https://raw.githubusercontent.com/blechschmidt/massdns/refs/heads/master/lists/resolvers.txt -O /app/resolvers.txt

# Copy Subfinder and Assetfinder binaries
COPY --from=builder /go/bin/subfinder /usr/local/bin/
COPY --from=builder /go/bin/assetfinder /usr/local/bin/

# Copy shared utility functions
COPY osint_domains_tools/utils_osint.py /app/utils_osint.py

# Copy runner script
COPY osint_domains_tools/runner.py /app/runner.py

# Copy configuration files
COPY osint_domains_tools/assetfinder.env /app/assetfinder.env
COPY osint_domains_tools/subfinder-config.yaml /app/subfinder-config.yaml

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PATH=/usr/local/bin:$PATH
ENV ASSETFINDER_ENV_FILE=/app/assetfinder.env
ENV SUBFINDER_CONFIG_FILE=/app/subfinder-config.yaml

# Set entrypoint to runner script
ENTRYPOINT ["python3", "/app/runner.py"]

