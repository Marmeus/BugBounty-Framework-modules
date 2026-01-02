#!/usr/bin/env python3
"""
DNS Brute Force Module - Standalone Entrypoint
Reads task from /task/input.json, generates wordlist and checks domains, writes NDJSON to /task/output.ndjson
Refactored from WORKER/Docker/bot/IG/dns_wordlist_generator.py and domain_checker.py
"""
import json
import os
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

# Import utility functions from utils_osint
sys.path.insert(0, '/app')
from utils_osint import (
    create_random_file,
    remove_file,
    save_list_to_file,
    file_to_list,
    read_errors,
    detect_domain_level,
    check_scope
)

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'


def write_error(message, level='ERROR'):
    """Write error/warning message to errors file"""
    with open(ERRORS_FILE, 'a') as f:
        f.write(f"[{level}] {message}\n")


def save_domain_to_file(domain, filename):
    """Save a single domain to a file"""
    with open(filename, 'w') as file:
        file.write(domain + '\n')


def append_wordlist_data(domain, output_file, env_vars):
    """Append wordlist data from amass and assetnote wordlists"""
    try:
        # Use environment variables for wordlist paths (from Dockerfile)
        wordlists_path = os.getenv('WORDLISTS_PATH', '/wordlists')
        cmd = f"cat {wordlists_path}/best-dns-wordlist.txt {wordlists_path}/amass-all.txt | sed 's/$/.{domain}/' | anew -q {output_file}"
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            env=env_vars
        )
    except Exception as e:
        write_error(f"BRUTE DOMAINS - WORDLIST GENERATOR Error: {e}")
        write_error(f"Stack trace: {traceback.format_exc()}")


def run_gotator(domain, output_file, error_file, env_vars):
    """Run gotator to generate subdomain permutations"""
    domain_file = ""
    try:
        domain_file = create_random_file()
        save_domain_to_file(domain, domain_file)
        
        # Use environment variables for wordlist paths (from Dockerfile)
        wordlists_path = os.getenv('WORDLISTS_PATH', '/wordlists')
        
        # Get debug from environment variable (from Dockerfile)
        debug = os.getenv('DEBUG', 'false').lower() in ('true', '1', 'yes')
        
        if debug:
            cmd = f"gotator -sub {domain_file} -perm {wordlists_path}/magnalsix.txt -depth 1 -numbers 0 -mindup -adv -md -silent 2>{error_file} | anew -q {output_file}"
        else:
            cmd = f"gotator -sub {domain_file} -perm {wordlists_path}/magnalsix.txt -depth 2 -numbers 1 -mindup -adv -md -silent 2>{error_file} | anew -q {output_file}"
        
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            env=env_vars
        )
    except Exception as e:
        write_error(f"BRUTE DOMAINS - GOTATOR Error: {e}")
        write_error(f"Stack trace: {traceback.format_exc()}")
    finally:
        if domain_file:
            remove_file(domain_file)


def generate_wordlist(domains, increase_depth, env_vars):
    """Generate wordlist using gotator and wordlist files"""
    results = {"output": [], "errors": []}
    new_domains = domains
    
    for i in range(increase_depth):
        scan_domains = new_domains
        for domain in scan_domains:
            output_file = ""
            gotator_error_file = ""
            try:
                print(f"BRUTE DOMAINS - Generating subdomains wordlist from domain '{domain}'...")
                
                output_file = create_random_file()
                gotator_error_file = create_random_file()
                
                # Obtain domains using gotator
                run_gotator(domain, output_file, gotator_error_file, env_vars)
                
                # Read error_file to obtain the errors
                error_content = read_errors(gotator_error_file)
                if error_content:
                    results["errors"].append(f"BRUTE DOMAINS - ERROR GOTATOR '{domain}': {error_content}")
                
                # Append to the gotator wordlist a bunch of subdomains to brute force from amass and assetnote wordlists
                append_wordlist_data(domain, output_file, env_vars)
                
                new_domains = file_to_list(output_file)
                if not new_domains:
                    print("BRUTE DOMAINS - No new domains found")
                    continue
                results["output"].extend(new_domains)
            except Exception as e:
                write_error(f"BRUTE DOMAINS - Error: {e}")
                write_error(f"Stack trace: {traceback.format_exc()}")
            finally:
                if gotator_error_file:
                    remove_file(gotator_error_file)
                if output_file:
                    remove_file(output_file)
    
    return results


def check_domains(domains, env_vars, tools=None):
    """Check if domains resolve using puredns"""
    results = {"output": [], "errors": []}
    error_file = ""
    domains_file = ""
    output_file = ""
    
    try:
        print("DOMAIN CHECKER - Storing domains in a temporary file")
        domains_file = create_random_file()
        output_file = create_random_file()
        error_file = create_random_file()
        save_list_to_file(domains, domains_file)
        
        print("DOMAIN CHECKER - Executing resolving domains")
        
        # Use environment variables for paths (from Dockerfile)
        massdns_path = os.getenv('MASSDNS_PATH', '/usr/local/bin/massdns')
        resolvers_path = os.getenv('RESOLVERS_PATH', '/resolvers/resolvers.txt')
        resolvers_trusted_path = os.getenv('RESOLVERS_TRUSTED_PATH', '/resolvers/resolvers-trusted.txt')
        
        cmd = (
            f"puredns resolve {domains_file} --bin {massdns_path} "
            f"-r {resolvers_path} --resolvers-trusted {resolvers_trusted_path} "
            f"-l 0 --rate-limit-trusted 500 --wildcard-tests 30 --wildcard-batch 1500000 -q "
            f"2>{error_file} | anew -q {output_file}"
        )
        
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            env=env_vars
        )
        
        resolved_domains = file_to_list(output_file)
        results['output'] = resolved_domains
        
        error_content = read_errors(error_file)
        if error_content:
            results["errors"].append(f"DOMAIN CHECKER - ERROR PUREDNS: {error_content}")
    except Exception as e:
        write_error(f"DOMAIN CHECKER - Error: {e}")
        write_error(f"Stack trace: {traceback.format_exc()}")
    finally:
        if domains_file:
            remove_file(domains_file)
        if error_file:
            remove_file(error_file)
        if output_file:
            remove_file(output_file)
    
    return results


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
    increase_depth = params.get('increase_depth', 1)
    tools = params.get('tools', None)
    # Debug is now controlled via DEBUG environment variable (from Dockerfile)
    
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
    
    # Get environment variables
    env_vars = os.environ.copy()
    
    # Step 1: Generate wordlist
    print(f"Running DNS brute force for {len(domains)} domains")
    wordlist_results = generate_wordlist(domains, increase_depth, env_vars)
    
    # Step 2: Check if generated domains resolve
    all_resolved_domains = []
    if wordlist_results["output"]:
        check_results = check_domains(wordlist_results["output"], env_vars, tools)
        all_resolved_domains = check_results["output"]
        
        # Write errors
        for error in wordlist_results["errors"] + check_results["errors"]:
            write_error(error, level='WARNING')
    else:
        # Write errors
        for error in wordlist_results["errors"]:
            write_error(error, level='WARNING')
    
    # Process resolved domains and write NDJSON
    records_written = 0
    with open(OUTPUT_FILE, 'w') as out_f:
        for domain in all_resolved_domains:
            try:
                # Compute level
                level = detect_domain_level(domain)
                
                # Check scope
                in_scope = check_scope(domain, in_scope_rules, out_scope_rules)
                
                # Build record
                if tools:
                    # If tools are specified, create structured data for database registration
                    record = {
                        "host": domain,
                        "program_id": program_id,
                        "in_scope": in_scope,
                        "tools": ["gotator"],
                        "level": level
                    }
                else:
                    # Simple format if domains are already registered
                    record = {
                        "host": domain,
                        "program_id": program_id
                    }
                
                # Write as NDJSON (one JSON object per line)
                out_f.write(json.dumps(record) + '\n')
                records_written += 1
                
            except Exception as e:
                write_error(f"Error processing domain {domain}: {e}")
    
    # Exit successfully
    if records_written == 0:
        write_error("No domains resolved", level='WARNING')
    else:
        print(f"DNS Brute Force - Found {records_written} resolved domains")
    
    sys.exit(0)


if __name__ == '__main__':
    print("Running DNS brute force (gotator + puredns)")
    main()

