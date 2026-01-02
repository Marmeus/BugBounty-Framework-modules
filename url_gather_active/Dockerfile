# URL Gather Active Module - katana only (active URL gathering)
FROM python:3.11-slim

# Install Go and build dependencies
RUN apt-get update && \
    apt-get install -y git gcc golang-go && \
    rm -rf /var/lib/apt/lists/*

# Install katana
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Remove Go and build dependencies to reduce image size (keep gcc if katana needs it)
RUN apt-get remove -y golang-go git && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir requests

# Copy runner script
COPY url_gather_active/runner.py /app/runner.py

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PATH=/usr/local/bin:/root/go/bin:$PATH

ENTRYPOINT ["python3", "-u", "/app/runner.py"]