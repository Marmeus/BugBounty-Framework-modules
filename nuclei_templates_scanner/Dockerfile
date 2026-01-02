# Nuclei Scanner Module
FROM projectdiscovery/nuclei:latest

# Install Python and dependencies
RUN apk add --no-cache python3 py3-pip

# Set working directory
WORKDIR /app

# Copy module code
COPY nuclei_templates_scanner/runner.py /app/runner.py
COPY nuclei_templates_scanner/issue.py /app/issue.py
# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PATH=/usr/local/bin:$PATH

# Nuclei ENV variables
ENV NUCLEI_RATE_LIMIT=150
ENV NUCLEI_CONCURRENCY=25
ENV NUCLEI_TIMEOUT=10
ENV NUCLEI_RETRIES=1
ENV NUCLEI_SEVERITY=
ENV NUCLEI_TAGS=
ENV NUCLEI_EXCLUDE_SEVERITY=info
ENV NUCLEI_EXCLUDE_TAGS=ssl,iot,network,fuzzing

# Update nuclei templates on build
RUN nuclei -update-templates

# COPY nuclei_templates_scanner/custom-templates /app/custom-templates
# ENV CUSTOM_NUCLEI_TEMPLATES_PATH=/app/custom-templates

ENTRYPOINT ["python3", "-u", "/app/runner.py"]

