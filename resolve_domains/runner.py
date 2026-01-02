#!/usr/bin/env python3
"""
Resolve Domains Module - DNS Resolution with dig
Reads task from /task/input.json, resolves domains using dig to collect DNS records,
writes DNS records as JSON to /task/output.ndjson

Note: puredns is available in the container and can be used for bulk resolution
checking, but dig is used here to get detailed DNS records (A, AAAA, CNAME, NS, MX, TXT).
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'

# Environment variables for puredns (if needed in future)
MASSDNS_PATH = os.getenv('MASSDNS_PATH', '/usr/local/bin/massdns')
RESOLVERS_PATH = os.getenv('RESOLVERS_PATH', '/resolvers/resolvers.txt')


def write_error(message, level='ERROR'):
    """Write error/warning message to errors file"""
    with open(ERRORS_FILE, 'a') as f:
        f.write(f"[{level}] {message}\n")




def query_dns_record(domain: str, record_type: str) -> List[str]:
    """
    Use dig to query a specific DNS record type
    
    Args:
        domain: Domain name to query
        record_type: DNS record type (A, AAAA, CNAME, NS, MX, TXT)
    
    Returns:
        List of record values
    """
    records = []
    
    try:
        # Run dig command
        cmd = ['dig', '+short', '+noall', '+answer', record_type, domain]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return records
        
        # Parse dig output
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # dig output format varies by record type
            # For A/AAAA: just IP
            # For CNAME: domain -> target
            # For NS: domain -> nameserver
            # For MX: priority domain
            # For TXT: "value"
            
            if record_type in ['A', 'AAAA']:
                # Just the IP address
                if line and ('.' in line or ':' in line):
                    records.append(line)
            elif record_type == 'CNAME':
                # Extract target (after last space or ->)
                parts = line.split()
                if len(parts) >= 2:
                    target = parts[-1].rstrip('.')
                    records.append(target)
            elif record_type == 'NS':
                # Extract nameserver
                parts = line.split()
                if len(parts) >= 2:
                    ns = parts[-1].rstrip('.')
                    records.append(ns)
            elif record_type == 'MX':
                # Format: priority domain
                parts = line.split()
                if len(parts) >= 2:
                    priority = parts[0]
                    mx_domain = parts[1].rstrip('.')
                    records.append(f"{priority} {mx_domain}")
            elif record_type == 'TXT':
                # Remove quotes and extract value
                value = line.strip('"').strip("'")
                if value:
                    records.append(value)
    
    except subprocess.TimeoutExpired:
        write_error(f"dig timeout for {domain} {record_type}", level='WARNING')
    except Exception as e:
        write_error(f"Error querying {record_type} for {domain}: {e}", level='WARNING')
    
    return records


def resolve_domain(domain: str) -> Dict[str, List[str]]:
    """
    Resolve all DNS records for a domain using dig
    
    Returns:
        Dictionary with record types as keys and lists of values
        Format: {"A": ["1.2.3.4"], "AAAA": [], "CNAME": [], "NS": [], "MX": [], "TXT": []}
    """
    dns_records = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "NS": [],
        "MX": [],
        "TXT": []
    }
    
    # Use dig for all record types (most reliable)
    # Query A, AAAA, CNAME, NS, MX, TXT records
    for record_type in ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT']:
        try:
            records = query_dns_record(domain, record_type)
            dns_records[record_type] = records
        except Exception as e:
            write_error(f"Error querying {record_type} for {domain}: {e}", level='WARNING')
    
    return dns_records


def main():
    """Main entry point"""
    # Read input.json
    try:
        with open(INPUT_FILE, 'r') as f:
            task = json.load(f)
    except FileNotFoundError:
        write_error(f"Input file not found: {INPUT_FILE}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        write_error(f"Invalid JSON in input file: {e}")
        sys.exit(1)
    except Exception as e:
        write_error(f"Error reading input file: {e}")
        sys.exit(1)
    
    # Extract task data
    program_id = task.get('program_id')
    params = task.get('params', {})
    domains = params.get('domains', [])
    
    if not domains:
        write_error("No domains provided in params.domains")
        sys.exit(1)
    
    if program_id is None:
        write_error("program_id not found in input")
        sys.exit(1)
    
    # Initialize output file (truncate if exists)
    output_path = Path(OUTPUT_FILE)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.touch()
    
    # Initialize errors file (truncate if exists)
    errors_path = Path(ERRORS_FILE)
    errors_path.parent.mkdir(parents=True, exist_ok=True)
    errors_path.touch()
    
    # Process each domain
    records_written = 0
    
    with open(OUTPUT_FILE, 'w') as out_f:
        for domain in domains:
            try:
                # Resolve DNS records
                dns_records = resolve_domain(domain)
                
                # Convert to JSON string
                resolved_json_str = json.dumps(dns_records)
                
                # Build record
                # Note: db_inserter expects 'host' as the domain column name
                record = {
                    "host": domain,
                    "program_id": program_id,
                    "resolved": resolved_json_str
                }
                
                # Write as NDJSON (one JSON object per line)
                out_f.write(json.dumps(record) + '\n')
                records_written += 1
                
                print(f"Resolved {domain}: {len(dns_records['A'])} A, {len(dns_records['AAAA'])} AAAA, "
                      f"{len(dns_records['CNAME'])} CNAME, {len(dns_records['NS'])} NS, "
                      f"{len(dns_records['MX'])} MX, {len(dns_records['TXT'])} TXT")
                
            except Exception as e:
                write_error(f"Error processing domain {domain}: {e}")
    
    # Exit successfully (even if there were warnings)
    if records_written == 0:
        write_error("No domains resolved", level='WARNING')
    
    print(f"Resolved {records_written} domain(s)")
    sys.exit(0)


if __name__ == '__main__':
    print("Running resolve_domains (puredns + dig)")
    main()

