#!/usr/bin/env python3
"""
Mantra Find Secrets Module - Standalone Entrypoint
Reads task from /task/input.json, scans URLs using mantra for API key leaks,
writes NDJSON issues to /task/output.ndjson
"""
import json
import os
import subprocess
import sys
import tempfile
import re
from pathlib import Path
from datetime import datetime, timezone
from issue import Issue

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'


def write_error(message, level='ERROR'):
    """Write error/warning message to errors file"""
    with open(ERRORS_FILE, 'a') as f:
        f.write(f"[{level}] {message}\n")


def parse_mantra_output(output_text: str, program_id: int):
    """
    Parse mantra output and create issues.
    Mantra outputs findings in the format: [+] <URL> [<found_string>]
    Example: [+] https://api.one.kaseya.com:443 [6Lelf0yIRsoDEaO4NwMed5sXl8KqlrkSAJAShCf1]
    Example: [+] http://lp.kaseya.com:80 [apiKey: 'public_a517d613d15109345a9e6f3792cebecc']
    
    Groups multiple found_strings per URL into a single issue.
    """
    issues = []
    if not output_text or not output_text.strip():
        return issues
    
    # Dictionary to group findings by URL: {url: [found_string1, found_string2, ...]}
    url_findings = {}
    
    lines = output_text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Only process lines starting with [+] (successful findings)
        # Ignore lines starting with [-] (errors)
        if not line.startswith('[+]'):
            continue
        
        # Parse format: [+] <URL> [<found_string>]
        # Extract URL and found string using regex
        # Pattern: [+] <URL> [<found_string>]
        # The found_string is everything between the last [ and ]
        match = re.match(r'\[\+\]\s+(.+?)\s+\[(.+)\]$', line)
        
        if not match:
            write_error(f"MANTRA_FIND_SECRETS - Unable to parse mantra output line: {line[:100]}", level='WARNING')
            continue
        
        found_url = match.group(1).strip()
        found_string = match.group(2).strip()
        
        # Group findings by URL
        if found_url not in url_findings:
            url_findings[found_url] = []
        url_findings[found_url].append(found_string)
    
    # Create one issue per URL with all found_strings
    for found_url, found_strings in url_findings.items():
        # Create description
        num_strings = len(found_strings)
        if num_strings == 1:
            description = f'API key leak detected on {found_url}. Found: {found_strings[0][:100]}'
        else:
            description = f'API key leaks detected on {found_url}. Found {num_strings} different strings.'
        
        # Create POC with all found_strings
        poc = "Found Strings:\n"+" ,".join(found_strings)
        
        issue = Issue(
            target=found_url,
            name="API Key Leak",
            severity="High",
            description=description,
            poc=poc,
            scanner="mantra",
            program_id=program_id,
            discovered_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        )
        issues.append(issue.to_dict())
    
    return issues


def run_mantra(urls_file: str, user_agent: str = None):
    """
    Run mantra against URLs from a file using stdin
    Command: cat <urls_file> | mantra -s -ua <user_agent>
    Returns: (success: bool, output: str, error: str)
    """
    try:
        # Check if mantra is available
        try:
            result = subprocess.run(['mantra', '-h'], 
                         capture_output=True, timeout=5, check=False)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            write_error("Mantra binary not found. Please ensure mantra is installed and in PATH.")
            return False, "", "Mantra binary not found"
        
        # Build mantra command
        # cat <urls_file> | mantra -s -ua <user_agent>
        mantra_cmd = ['mantra', '-s']
        
        if user_agent:
            mantra_cmd.extend(['-ua', user_agent])
        
        print(f"MANTRA_FIND_SECRETS - Scanning URLs from file: {urls_file}")
        if user_agent:
            print(f"MANTRA_FIND_SECRETS - Using user agent: {user_agent}")
        
        # Execute: cat <urls_file> | mantra -s -ua <user_agent>
        cmd = f"cat {urls_file} | {' '.join(mantra_cmd)} | sed -r 's/\x1B\[[0-9;]*m//g'"
        
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        
        # Check for errors
        if result.stderr:
            error_msg = f"MANTRA_FIND_SECRETS - stderr: {result.stderr}"
            write_error(error_msg, level='WARNING')
        
        if result.returncode != 0:
            error_msg = f"MANTRA_FIND_SECRETS - mantra returned non-zero exit code {result.returncode}"
            write_error(error_msg, level='WARNING')
            # Mantra may return non-zero even with valid findings, so we continue
        
        print(f"MANTRA_FIND_SECRETS - mantra output:\n{result.stdout}")
        return True, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        error_msg = "MANTRA_FIND_SECRETS - mantra timeout"
        write_error(error_msg)
        return False, "", "Timeout"
    except Exception as e:
        error_msg = f"MANTRA_FIND_SECRETS - Error running mantra: {e}"
        write_error(error_msg)
        return False, "", str(e)


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
    urls = params.get('urls', [])
    
    if not urls:
        write_error("No URLs provided in params.urls")
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
    
    # Get user agent from environment variable
    user_agent = os.getenv('MANTRA_USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
    
    # Create temporary file for URLs
    urls_file = ""
    all_issues = []
    
    try:
        print(f"MANTRA_FIND_SECRETS - Starting scan for {len(urls)} URLs")
        
        # Create temporary file and write all URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
            urls_file = tmp_file.name
            for url in urls:
                tmp_file.write(f"{url}\n")
        
        print(f"MANTRA_FIND_SECRETS - Stored {len(urls)} URLs in temporary file: {urls_file}")
        
        # Run mantra once with all URLs
        success, output, error = run_mantra(urls_file, user_agent)
        
        if success and output:
            # Parse output and create issues
            # Note: parse_mantra_output extracts URLs from the output itself
            all_issues = parse_mantra_output(output, program_id)
            if all_issues:
                print(f"MANTRA_FIND_SECRETS - Found {len(all_issues)} API key leaks")
        elif error:
            write_error(f"MANTRA_FIND_SECRETS - Error running mantra: {error}", level='WARNING')
        
        print(f"MANTRA_FIND_SECRETS - Found {len(all_issues)} total API key leaks")
        
        # Write NDJSON output
        records_written = 0
        with open(OUTPUT_FILE, 'w') as out_f:
            for record in all_issues:
                try:
                    # Write as NDJSON (one JSON object per line)
                    out_f.write(json.dumps(record) + '\n')
                    records_written += 1
                except Exception as e:
                    write_error(f"Error writing record: {e}")
        
        if records_written == 0:
            write_error("No API key leaks found", level='WARNING')
        else:
            print(f"MANTRA_FIND_SECRETS - Wrote {records_written} issue records")
        
    except Exception as e:
        error_msg = f"MANTRA_FIND_SECRETS - Error: {e}"
        write_error(error_msg)
        sys.exit(1)
    finally:
        # Clean up temporary file
        if urls_file and os.path.exists(urls_file):
            try:
                os.remove(urls_file)
            except Exception as e:
                write_error(f"MANTRA_FIND_SECRETS - Error removing temp file {urls_file}: {e}", level='WARNING')
    
    sys.exit(0)


if __name__ == '__main__':
    print("Running mantra to find API key leaks")
    main()

