# Python Templates Scanner Module - Uses oddin library
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY python_templates_scanner/requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy odin library (should be copied into module directory before build)
# The odin library directory should be placed in python_templates_scanner/odin/
COPY python_templates_scanner/odin /app/odin
COPY python_templates_scanner/runner.py /app/
COPY python_templates_scanner/check_loader.py /app/
COPY python_templates_scanner/issue.py /app/

# Copy checks
COPY python_templates_scanner/checks/ /app/checks/


ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV ODIN_MAX_WORKERS=20

CMD ["python3", "/app/runner.py"]

