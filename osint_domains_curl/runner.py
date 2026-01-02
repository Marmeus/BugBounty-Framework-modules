#!/usr/bin/env python3
"""
OSINT Domains Curl Module - Standalone Entrypoint
Reads task from /task/input.json, runs curl-based OSINT APIs, writes NDJSON to /task/output.ndjson
"""
import json
import os
import subprocess
import sys
import tempfile
import concurrent.futures
import re
from pathlib import Path

# Import utility functions from utils_osint
sys.path.insert(0, '/app')
from utils_osint import detect_domain_level, check_scope

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'


def write_error(message, level='ERROR'):
    """Write error/warning message to errors file"""
    with open(ERRORS_FILE, 'a') as f:
        f.write(f"[{level}] {message}\n")


def run_curl_command(cmd: str, tool_name: str, error_file: str):
    """Run a single curl command and return success status"""
    curl_timeout = os.getenv('CURL_TIMEOUT')
    curl_timeout = int(curl_timeout) if curl_timeout else None
    
    try:
        result = subprocess.run(
            [cmd],
            capture_output=True,
            text=True,
            shell=True,
            timeout=curl_timeout
        )
        if result.returncode != 0:
            with open(error_file, 'a') as f:
                f.write(f"{tool_name} error: {result.stderr}\n")
            write_error(f"{tool_name} returned non-zero exit code: {result.returncode}", level='WARNING')
        return True
    except subprocess.TimeoutExpired:
        timeout_msg = f"{curl_timeout} seconds" if curl_timeout else "configured timeout"
        write_error(f"{tool_name} timed out after {timeout_msg}", level='WARNING')
        with open(error_file, 'a') as f:
            f.write(f"{tool_name} timeout after {timeout_msg}\n")
        return False
    except Exception as e:
        write_error(f"{tool_name} error: {e}")
        with open(error_file, 'a') as f:
            f.write(f"{tool_name} exception: {str(e)}\n")
        return False


def execute_curl_commands(domain: str, output_dir: str, error_file: str):
    """Execute curl commands for various OSINT APIs in parallel
    
    Returns:
        List of error messages for tools that timed out or failed
    """
    timeout_errors = []
    
    try:
        # Define all curl commands
        curl_commands = [
            # RapidDNS
            (rf"""curl -sSk "https://rapiddns.io/subdomain/{domain}?full=1#result" 2>>{error_file} | grep -i {domain} | grep -i "<td>" | grep -vi "href" | sort -u | sed 's/<td>//g' | sed 's/<\/td>//g' | tr '[:upper:]' '[:lower:]' > {output_dir}/rapiddns.txt""", "rapiddns"),
            
            # CertSpotter - suppress jq errors for invalid JSON
            (rf"""curl -sSk "https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names&include_subdomains=true" 2>>{error_file} | jq -r '.[].dns_names[]?' 2>/dev/null | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | tr '[:upper:]' '[:lower:]' | sort -u > {output_dir}/certspotter.txt""", "certspotter"),
            
            # Web Archive - filter HTML error responses
            (rf"""curl -sSk "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey" 2>>{error_file} | grep -v -iE "(html|body|h1|gateway|time-out|timeout|504|500|502|503|error)" | sed -e 's_https*://__' -e "s/\/.*//" | sed 's/:.*//' | tr '[:upper:]' '[:lower:]' | sort -u > {output_dir}/web_archive.txt""", "web_archive"),
            
            # JLDC
            (rf"""curl -sSk "https://jldc.me/anubis/subdomains/{domain}" 2>>{error_file} | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | tr '[:upper:]' '[:lower:]' | sort -u > {output_dir}/jldc.txt""", "jldc"),
            
            # crt.sh - suppress jq errors for invalid JSON
            (rf"""curl -sSk "https://crt.sh?q=%.{domain}&output=json" 2>>{error_file} | jq -r ".[].common_name,.[].name_value" 2>/dev/null | cut -d'"' -f2 | sed 's/\\n/\n/g' | sed 's/\*.//g'| sed -r 's/([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})//g' | tr '[:upper:]' '[:lower:]' | sort -u > {output_dir}/crt.txt""", "crt"),
            
            # HackerTarget
            (rf"""curl -sSk "https://api.hackertarget.com/hostsearch/?q={domain}" 2>>{error_file} | cut -d',' -f1  | tr '[:upper:]' '[:lower:]' | sort -u > {output_dir}/hackertarget.txt""", "hackertarget"),
        ]
        
        # Execute all curl commands in parallel using ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            # Submit all tasks
            future_to_tool = {
                executor.submit(run_curl_command, cmd, tool_name, error_file): tool_name
                for cmd, tool_name in curl_commands
            }
            
            # Wait for all tasks to complete
            for future in concurrent.futures.as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    success = future.result()
                    if not success:
                        timeout_errors.append(f"{tool_name} failed or timed out for domain {domain}")
                except Exception as e:
                    write_error(f"{tool_name} generated an exception: {e}")
                    timeout_errors.append(f"{tool_name} exception for domain {domain}: {e}")
        
    except Exception as e:
        write_error(f"OSINT - CURLS Error for {domain}: {e}")
        timeout_errors.append(f"OSINT - CURLS Error for {domain}: {e}")
    
    return timeout_errors


def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name (including wildcards)
    
    Valid examples:
    - example.com
    - sub.example.com
    - *.example.com
    - *.*.example.com
    """
    if not domain or len(domain) < 3:
        return False
    
    domain_lower = domain.lower()
    
    # Filter out common HTML error patterns
    error_patterns = [
        'html', 'body', 'h1', 'h2', 'h3', 'gateway', 'time-out', 'timeout',
        '504', '500', '502', '503', 'error', 'not found', 'unavailable'
    ]
    if any(pattern in domain_lower for pattern in error_patterns):
        return False
    
    # Check if it looks like HTML tags
    if '<' in domain or '>' in domain:
        return False
    
    # Remove wildcard prefixes for validation (e.g., *.example.com -> example.com)
    domain_to_validate = domain_lower
    if domain_to_validate.startswith('*.'):
        domain_to_validate = domain_to_validate[2:]  # Remove '*.' prefix
    # Handle multiple wildcard levels (e.g., *.*.example.com)
    while domain_to_validate.startswith('*.'):
        domain_to_validate = domain_to_validate[2:]
    
    # After removing wildcards, should have at least one dot (TLD)
    if '.' not in domain_to_validate:
        return False
    
    # Basic domain pattern: alphanumeric, dots, hyphens
    # Allow wildcards at the beginning
    if domain_lower.startswith('*'):
        # For wildcard domains, validate the part after wildcards
        if not re.match(r'^(\*\.)*[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain_lower):
            return False
    else:
        # For regular domains, standard validation
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain_lower):
            return False
    
    return True


def read_output_and_classify_by_tool(output_dir: str):
    """Read output files and classify domains by tool"""
    osint_domains = {}
    
    try:
        if not os.path.exists(output_dir):
            return osint_domains
            
        files = os.listdir(output_dir)
        for file_name in files:
            file_path = os.path.join(output_dir, file_name)
            if not os.path.isfile(file_path):
                continue
                
            tool = file_name.split('.')[0]
            tool_domains = []
            try:
                with open(file_path, 'r') as file:
                    file_content = file.readlines()
                for line in file_content:
                    domain = line.strip()
                    # Validate domain before adding (allows wildcards)
                    if domain and is_valid_domain(domain):
                        tool_domains.append(domain)
                        if domain not in osint_domains:
                            osint_domains[domain] = [tool]
                        elif domain in osint_domains:
                            if tool not in osint_domains[domain]:
                                osint_domains[domain].append(tool)
                
                # Output domains found by this tool
                if tool_domains:
                    print(f"{tool.upper()} found {len(tool_domains)} domain(s):")
                    for domain in sorted(tool_domains):
                        print(f"  - {domain}")
                else:
                    print(f"{tool.upper()} found 0 domains")
                    
            except Exception as e:
                write_error(f"Error reading {file_path}: {e}", level='WARNING')
    except Exception as e:
        write_error(f"OSINT - Reading output files - Error: {e}")
    
    return osint_domains


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
    in_scope_rules = params.get('in_scope_rules', [])
    out_scope_rules = params.get('out_scope_rules', [])
    max_level = params.get('max_level')  # Optional
    
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
    all_discovered = {}  # domain -> list of tools
    
    for domain in domains:
        try:
            print(f"\n{'='*60}")
            print(f"Processing domain: {domain}")
            print(f"{'='*60}")
            
            # Create temporary output directory
            output_dir = tempfile.mkdtemp()
            error_file = os.path.join(output_dir, 'errors.txt')
            
            # Execute curl commands and get timeout errors
            curl_timeout_errors = execute_curl_commands(domain, output_dir, error_file)
            
            # Add timeout errors to errors file
            for timeout_error in curl_timeout_errors:
                write_error(f"OSINT - {timeout_error}", level='WARNING')
            
            # Classify domains by tool
            osint_domains = read_output_and_classify_by_tool(output_dir)
            
            # Merge into all_discovered
            for osint_domain, tools in osint_domains.items():
                if osint_domain not in all_discovered:
                    all_discovered[osint_domain] = tools
                else:
                    # Merge tools lists
                    for tool in tools:
                        if tool not in all_discovered[osint_domain]:
                            all_discovered[osint_domain].append(tool)
            
            # Read errors from error file if any
            if os.path.exists(error_file):
                with open(error_file, 'r') as f:
                    error_content = f.read().strip()
                    if error_content:
                        write_error(f"OSINT - ERROR DOMAIN '{domain}': {error_content}", level='WARNING')
            
            # Clean up temp directory
            import shutil
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
                
        except Exception as e:
            write_error(f"Error processing domain {domain}: {e}")
    
    # Process discovered domains and write NDJSON
    print(f"\n{'='*60}")
    print(f"SUMMARY: Found {len(all_discovered)} unique domain(s) across all tools")
    print(f"{'='*60}")
    
    records_written = 0
    with open(OUTPUT_FILE, 'w') as out_f:
        for disc_domain in sorted(all_discovered.keys()):
            try:
                # Compute level
                level = detect_domain_level(disc_domain)
                
                # Apply max_level filter if specified
                if max_level is not None and level > max_level:
                    continue
                
                # Check scope
                in_scope = check_scope(disc_domain, in_scope_rules, out_scope_rules)
                
                # Get tools list
                tools = all_discovered[disc_domain]
                
                # Build record
                record = {
                    "host": disc_domain,
                    "program_id": program_id,
                    "in_scope": in_scope,
                    "tools": tools,  # List of tools that found this domain
                    "level": level
                }
                
                # Write as NDJSON (one JSON object per line)
                out_f.write(json.dumps(record) + '\n')
                records_written += 1
                
            except Exception as e:
                write_error(f"Error processing discovered domain {disc_domain}: {e}")
    
    # Exit successfully (even if there were warnings)
    if records_written == 0:
        write_error("No domains discovered", level='WARNING')
    
    sys.exit(0)


if __name__ == '__main__':
    print("Running curl-based OSINT")
    main()


