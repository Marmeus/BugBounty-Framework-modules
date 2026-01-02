#!/usr/bin/env python3
"""
OSINT Domains Tools Module - Standalone Entrypoint
Reads task from /task/input.json, runs subfinder and assetfinder, writes NDJSON to /task/output.ndjson
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Import utility functions from utils_osint
sys.path.insert(0, '/app')
from utils_osint import detect_domain_level, check_scope

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'

# Optional resolvers path
RESOLVERS_TRUSTED_PATH = os.getenv('RESOLVERS_TRUSTED_PATH', '/app/resolvers.txt')

# Configuration file paths
ASSETFINDER_ENV_FILE = os.getenv('ASSETFINDER_ENV_FILE', '/app/assetfinder.env')
SUBFINDER_CONFIG_FILE = os.getenv('SUBFINDER_CONFIG_FILE', '/app/subfinder-config.yaml')


def write_error(message, level='ERROR'):
    """Write error/warning message to errors file"""
    with open(ERRORS_FILE, 'a') as f:
        f.write(f"[{level}] {message}\n")


def load_assetfinder_env():
    """Load assetfinder environment variables from file
    
    Returns:
        dict: Environment variables dict, merged with os.environ
    """
    env_vars = os.environ.copy()
    
    if not os.path.exists(ASSETFINDER_ENV_FILE):
        write_error(f"Assetfinder env file not found: {ASSETFINDER_ENV_FILE}. Using defaults.", level='WARNING')
        return env_vars
    
    try:
        with open(ASSETFINDER_ENV_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                # Parse KEY=value format
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    # Only set if key is not empty
                    if key:
                        env_vars[key] = value
    except Exception as e:
        write_error(f"Error loading assetfinder env file: {e}", level='WARNING')
    
    return env_vars


def run_subfinder(domain, output_file):
    """Execute subfinder for a domain and return discovered domains"""
    discovered_domains = []
    
    try:
        # Check if subfinder is available
        try:
            result = subprocess.run(['subfinder', '-version'], 
                         capture_output=True, timeout=5, check=True)
            subfinder_version = result.stderr
            print(f"Subfinder version: {subfinder_version}")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            write_error(f"Subfinder binary not found. Please ensure subfinder is installed and in PATH.")
            return discovered_domains
        
        # Build subfinder command
        subfinder_cmd = [
            'subfinder',
            '-silent',
            '-all',
            '-d', domain,
            '-o', output_file
        ]
        
        # Add config file if available
        if os.path.exists(SUBFINDER_CONFIG_FILE):
            subfinder_cmd.extend(['-pc', SUBFINDER_CONFIG_FILE])
        
        # Add resolvers if available (optional)
        if os.path.exists(RESOLVERS_TRUSTED_PATH):
            subfinder_cmd.extend(['-rL', RESOLVERS_TRUSTED_PATH])
        
        # Execute subfinder
        result = subprocess.run(
            subfinder_cmd,
            capture_output=True,
            text=True,
            timeout=None  # Use worker timeout
        )
        
        print(f"Subfinder result:\n{result.stdout}")
        # Write stderr to errors file (subfinder uses stderr for output)
        if result.stderr:
            # Truncate if too long
            stderr_content = result.stderr
            if len(stderr_content) > 1000:
                stderr_content = stderr_content[:1000] + "... (truncated)"
            write_error(f"Subfinder stderr for {domain}: {stderr_content}", level='WARNING')
        
        if result.returncode != 0:
            write_error(f"Subfinder returned non-zero exit code {result.returncode} for {domain}", level='WARNING')
        
        # Read discovered domains from output file
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    domain_found = line.strip()
                    if domain_found:
                        discovered_domains.append(domain_found)
        
    except subprocess.TimeoutExpired:
        write_error(f"Subfinder timeout for {domain}", level='WARNING')
    except FileNotFoundError as e:
        write_error(f"Subfinder binary not found: {e}")
    except Exception as e:
        write_error(f"Error running subfinder for {domain}: {e}")
    
    return discovered_domains


def run_assetfinder(domain):
    """Execute assetfinder for a domain and return discovered domains"""
    discovered_domains = []
    
    try:
        # Check if assetfinder is available
        try:
            result = subprocess.run(['assetfinder', '--help'], 
                         capture_output=True, timeout=5, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            write_error(f"Assetfinder binary not found. Please ensure assetfinder is installed and in PATH.")
            return discovered_domains
        
        # Load environment variables from file
        env_vars = load_assetfinder_env()
    
        # Build assetfinder command
        assetfinder_cmd = ['assetfinder', domain]
        

        # Print assetfinder environment variables
        print(f"Assetfinder environment variables: {env_vars}")
        print(f"Assetfinder command: {assetfinder_cmd}")

        # Execute assetfinder
        result = subprocess.run(
            assetfinder_cmd,
            capture_output=True,
            text=True,
            env=env_vars,
            timeout=None  # Use worker timeout
        )
        
        print(f"Assetfinder result:\n{result.stdout}")
        if result.stderr:
            # Truncate if too long
            stderr_content = result.stderr
            if len(stderr_content) > 1000:
                stderr_content = stderr_content[:1000] + "... (truncated)"
            write_error(f"Assetfinder stderr for {domain}: {stderr_content}", level='WARNING')
        
        if result.returncode != 0:
            write_error(f"Assetfinder returned non-zero exit code {result.returncode} for {domain}", level='WARNING')
        
        # Parse discovered domains from stdout (one per line)
        if result.stdout:
            for line in result.stdout.split('\n'):
                domain_found = line.strip()
                if domain_found:
                    discovered_domains.append(domain_found)
        
    except subprocess.TimeoutExpired:
        write_error(f"Assetfinder timeout for {domain}", level='WARNING')
    except FileNotFoundError as e:
        write_error(f"Assetfinder binary not found: {e}")
    except Exception as e:
        write_error(f"Error running assetfinder for {domain}: {e}")
    
    return discovered_domains


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
    all_discovered = {}  # dict: domain -> set of tools that found it
    
    for domain in domains:
        try:
            # Create temporary output file for subfinder
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
                tmp_output = tmp_file.name
            
            # Run subfinder
            subfinder_domains = run_subfinder(domain, tmp_output)
            for disc_domain in subfinder_domains:
                if disc_domain not in all_discovered:
                    all_discovered[disc_domain] = set()
                all_discovered[disc_domain].add('subfinder')
            
            # Run assetfinder
            assetfinder_domains = run_assetfinder(domain)
            for disc_domain in assetfinder_domains:
                if disc_domain not in all_discovered:
                    all_discovered[disc_domain] = set()
                all_discovered[disc_domain].add('assetfinder')
            
            # Clean up temp file
            if os.path.exists(tmp_output):
                os.remove(tmp_output)
                
        except Exception as e:
            write_error(f"Error processing domain {domain}: {e}")
    
    # Process discovered domains and write NDJSON
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
                
                # Build tools string (comma-separated, sorted)
                tools_str = sorted(all_discovered[disc_domain])
                
                # Build record
                record = {
                    "host": disc_domain,
                    "program_id": program_id,
                    "in_scope": in_scope,
                    "tools": tools_str,  # e.g., "assetfinder,subfinder" or "subfinder"
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
    print("Running osint_domains_tools (subfinder + assetfinder)")
    main()

