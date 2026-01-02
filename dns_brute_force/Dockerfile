# DNS Brute Force Module - gotator, puredns, massdns
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Install DNS brute force tools
RUN go install github.com/Josue87/gotator@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/tomnomnom/anew@latest

# Compile MassDNS
RUN git clone https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make && \
    cp bin/massdns /tmp/massdns

# Final stage
FROM python:3.11-slim

# Copy binaries from builder
COPY --from=builder /go/bin/gotator /usr/local/bin/
COPY --from=builder /go/bin/puredns /usr/local/bin/
COPY --from=builder /go/bin/anew /usr/local/bin/
COPY --from=builder /tmp/massdns /usr/local/bin/massdns

# Install minimal dependencies
RUN apt-get update && \
    apt-get install -y curl jq wget && \
    rm -rf /var/lib/apt/lists/*

# Create wordlists directory
RUN mkdir -p /wordlists /resolvers

# Download wordlists
RUN wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O /wordlists/best-dns-wordlist.txt && \
    wget https://raw.githubusercontent.com/owasp-amass/amass/master/examples/wordlists/all.txt -O /wordlists/amass-all.txt && \
    wget https://raw.githubusercontent.com/blechschmidt/massdns/refs/heads/master/lists/resolvers.txt -O /resolvers/resolvers.txt

# Download components for magnalsix.txt
RUN cd /tmp && \
    wget https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt -O six2dez.txt && \
    wget https://raw.githubusercontent.com/subfinder/goaltdns/master/words.txt -O goaltdns.txt && \
    wget https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -O altdns.txt && \
    wget https://raw.githubusercontent.com/owasp-amass/amass/master/examples/wordlists/deepmagic.com_top500prefixes.txt -O magicTop500.txt

WORKDIR /app

# Copy module code
COPY dns_brute_force/utils_osint.py /app/utils_osint.py
COPY dns_brute_force/dns_brute_force.py /app/dns_brute_force.py
COPY dns_brute_force/runner.py /app/runner.py

# Combine wordlists with anew (now available)
RUN cat /tmp/six2dez.txt /tmp/goaltdns.txt /tmp/altdns.txt /tmp/magicTop500.txt | anew -q /wordlists/magnalsix.txt && \
    rm -f /tmp/six2dez.txt /tmp/goaltdns.txt /tmp/altdns.txt /tmp/magicTop500.txt

# Set default wordlist path
ENV WORDLISTS_PATH=/wordlists
ENV MASSDNS_PATH=/usr/local/bin/massdns
ENV RESOLVERS_PATH=/resolvers/resolvers.txt
ENV RESOLVERS_TRUSTED_PATH=/resolvers/resolvers-trusted.txt
ENV DEBUG=false
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PATH=/usr/local/bin:$PATH

ENTRYPOINT ["python3", "-u", "/app/runner.py"]
