#!/usr/bin/env python3
"""
OSINT Domains Amass Module - Standalone Entrypoint
Reads task from /task/input.json, runs amass, writes NDJSON to /task/output.ndjson
"""
import json
import os
import subprocess
import sys
import tempfile
import shutil
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


def run_amass(domain: str, output_file: str, error_file: str):
    """Execute amass for a domain and return discovered domains"""
    discovered_domains = []
    amass_temp_dir = ""
    
    try:
        # Check if amass is available
        try:
            result = subprocess.run(['amass', '-version'], 
                         capture_output=True, timeout=5, check=True)
            amass_version = result.stdout.decode() if result.stdout else result.stderr.decode()
            print(f"Amass version: {amass_version}")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            write_error(f"Amass binary not found. Please ensure amass is installed and in PATH.")
            return discovered_domains
        
        # Create temporary directory for amass
        amass_temp_dir = tempfile.mkdtemp()
        
        # Get timeout from env var, default to None (unlimited)
        amass_timeout = os.getenv('AMASS_TIMEOUT')
        amass_timeout = int(amass_timeout) if amass_timeout else None
        
        # Build amass command (runs without config file, uses default data sources)
        amass_cmd = [
            'amass', 'enum',
            '-passive',
            '-silent',
            '-d', domain,
            '-timeout', '180',
            '-dir', amass_temp_dir,
            '-o', output_file
        ]
        
        # Execute amass
        result = subprocess.run(
            amass_cmd,
            capture_output=True,
            text=True,
            timeout=amass_timeout
        )
        print(f"Amass result:\n{result.stdout}")
        # Write stderr to error file
        if result.stderr:
            with open(error_file, 'a') as f:
                f.write(result.stderr)
            # Truncate if too long
            stderr_content = result.stderr
            if len(stderr_content) > 1000:
                stderr_content = stderr_content[:1000] + "... (truncated)"
            write_error(f"Amass stderr for {domain}: {stderr_content}", level='WARNING')
        
        if result.returncode != 0:
            write_error(f"Amass returned non-zero exit code {result.returncode} for {domain}", level='WARNING')
        
        # Extract domains from amass output file
        if os.path.exists(output_file):
            discovered_domains = extract_amass_domains(output_file)
        
    except subprocess.TimeoutExpired:
        timeout_msg = f"{amass_timeout} seconds" if amass_timeout else "configured timeout"
        write_error(f"Amass timeout for {domain} after {timeout_msg}", level='WARNING')
    except FileNotFoundError as e:
        write_error(f"Amass binary not found: {e}")
    except Exception as e:
        write_error(f"Error running amass for {domain}: {e}")
    finally:
        # Clean up temp directory
        if amass_temp_dir and os.path.exists(amass_temp_dir):
            shutil.rmtree(amass_temp_dir)
    
    return discovered_domains


def extract_amass_domains(amass_file: str):
    """Extract domains from amass output using grep/awk command"""
    domains = []
    try:
        if not os.path.exists(amass_file):
            return domains
        
        # Use the command: cat amass.txt | grep FQDN | awk '{print $1}' | sort -u
        extract_timeout = os.getenv('AMASS_EXTRACT_TIMEOUT')
        extract_timeout = int(extract_timeout) if extract_timeout else None
        
        cmd = f"cat {amass_file} | grep FQDN | awk '{{print $1}}' | sort -u"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=extract_timeout
        )
        
        if result.returncode == 0 and result.stdout:
            domains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        else:
            # Fallback: if grep doesn't find FQDN, try reading file directly
            with open(amass_file, 'r') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        domains.append(domain)
            domains = sorted(set(domains))  # Remove duplicates and sort
                
    except subprocess.TimeoutExpired:
        write_error("Timeout extracting domains from amass output", level='WARNING')
    except Exception as e:
        write_error(f"Error extracting domains from amass output: {e}", level='WARNING')
    
    return domains


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
    all_discovered = set()  # Use set to avoid duplicates
    
    for domain in domains:
        try:
            # Create temporary output file for amass
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
                tmp_output = tmp_file.name
            
            # Create temporary error file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_err:
                tmp_error_file = tmp_err.name
            
            # Run amass
            discovered = run_amass(domain, tmp_output, tmp_error_file)
            
            # Collect discovered domains
            for disc_domain in discovered:
                all_discovered.add(disc_domain)
            
            # Read errors from error file if any
            if os.path.exists(tmp_error_file):
                with open(tmp_error_file, 'r') as f:
                    error_content = f.read().strip()
                    if error_content:
                        write_error(f"OSINT - ERROR DOMAIN '{domain}': {error_content}", level='WARNING')
            
            # Clean up temp files
            if os.path.exists(tmp_output):
                os.remove(tmp_output)
            if os.path.exists(tmp_error_file):
                os.remove(tmp_error_file)
                
        except Exception as e:
            write_error(f"Error processing domain {domain}: {e}")
    
    # Process discovered domains and write NDJSON
    records_written = 0
    with open(OUTPUT_FILE, 'w') as out_f:
        for disc_domain in sorted(all_discovered):
            try:
                # Compute level
                level = detect_domain_level(disc_domain)
                
                # Apply max_level filter if specified
                if max_level is not None and level > max_level:
                    continue
                
                # Check scope
                in_scope = check_scope(disc_domain, in_scope_rules, out_scope_rules)
                
                # Build record
                record = {
                    "host": disc_domain,
                    "program_id": program_id,
                    "in_scope": in_scope,
                    "tools": ["amass"],  # Consistent string format
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
    print("Running amass")
    main()

