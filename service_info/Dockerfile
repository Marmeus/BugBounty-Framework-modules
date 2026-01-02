# Server Info HTTPX Module - httpx + nuclei with screenshots
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Install httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Final stage
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for Chrome and nuclei
RUN apt-get update && \
    apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    git \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy httpx and nuclei binaries
COPY --from=builder /go/bin/httpx /usr/local/bin/
COPY --from=builder /go/bin/nuclei /usr/local/bin/

# Detect architecture and install Chrome accordingly
RUN arch=$(dpkg --print-architecture) && \
    if [ "$arch" = "amd64" ]; then \
        wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /etc/apt/trusted.gpg.d/google-chrome.gpg && \
        echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list && \
        apt-get update && \
        apt-get install -y google-chrome-stable; \
    elif [ "$arch" = "arm64" ]; then \
        apt-get update && \
        apt-get install -y chromium-browser && \
        ln -s /usr/bin/chromium-browser /usr/bin/google-chrome; \
    else \
        echo "Unsupported architecture: $arch"; \
        exit 1; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# Install Nuclei templates
RUN nuclei -update-templates
# Required to finish installing chrome headless
RUN nuclei -id screenshot -headless -c 25 -rl 150 -retries 1 -bs 25  -u https://marmeus.com

# Create necessary directories
RUN mkdir -p /tmp/nuclei-mounts /app/screenshots && \
    chmod 777 /tmp/nuclei-mounts

# Set Chrome path for nuclei
ENV CHROME_PATH=/usr/bin/google-chrome

WORKDIR /app

# Copy shared utility functions (not needed for this module but keeping for consistency)
COPY service_info/utils_osint.py /app/utils_osint.py

# Copy runner script and make executable
COPY service_info/runner.py /app/runner.py

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PATH=/usr/local/bin:$PATH
ENV HTTPX_TIMEOUT=1800
ENV HTTPX_THREADS=100 
ENV HTTPX_DELAY=200ms
ENV HTTPX_PORTS=80,443,8080,8443,8000,3000,5000
ENV HTTPX_USER_AGENT="Mozilla/5.0 (Linux; Android 9; ASUS_X00TD; Flow) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/359.0.0.288 Mobile Safari/537.36"

# Set entrypoint to runner script
ENTRYPOINT ["python3", "/app/runner.py"]

