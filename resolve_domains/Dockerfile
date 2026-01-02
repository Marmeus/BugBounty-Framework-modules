# Resolve Domains Module - puredns and dig for DNS resolution
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Install puredns
RUN go install github.com/d3mondev/puredns/v2@latest

# Compile MassDNS (required by puredns)
RUN git clone https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make && \
    cp bin/massdns /tmp/massdns

# Final stage
FROM python:3.11-slim

# Copy binaries from builder
COPY --from=builder /go/bin/puredns /usr/local/bin/
COPY --from=builder /tmp/massdns /usr/local/bin/massdns

# Install dig (dnsutils) and other utilities
RUN apt-get update && \
    apt-get install -y dnsutils curl wget jq && \
    rm -rf /var/lib/apt/lists/*

# Create resolvers directory
RUN mkdir -p /resolvers

# Download resolvers list
RUN wget https://raw.githubusercontent.com/blechschmidt/massdns/refs/heads/master/lists/resolvers.txt -O /resolvers/resolvers.txt 

WORKDIR /app

# Copy runner script
COPY resolve_domains/runner.py /app/runner.py

# Set environment variables
ENV MASSDNS_PATH=/usr/local/bin/massdns
ENV RESOLVERS_PATH=/resolvers/resolvers.txt
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PATH=/usr/local/bin:$PATH

ENTRYPOINT ["python3", "/app/runner.py"]

