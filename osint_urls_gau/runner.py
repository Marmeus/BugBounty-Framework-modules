#!/usr/bin/env python3
"""
OSINT URLs GAU Module - Standalone Entrypoint
Reads task from /task/input.json, gathers URLs using gau (passive), writes NDJSON to /task/output.ndjson
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import hashlib
import requests
import concurrent.futures
from datetime import datetime
from pathlib import Path
from utils_osint import write_error, get_hash, get_timestamp, file_to_list
# Disable SSL warnings for unverified HTTPS requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'

# File extensions to exclude
EXCLUDED_EXTENSIONS = r'\.(jpeg|jpg|ttf|woff|woff2|svg|png|ico|css|mp3|gif|mp4|eot|gif|wolf)'


def save_list_to_file(items, file_path):
    """Save list of items to file (one per line)"""
    with open(file_path, 'w') as f:
        for item in items:
            f.write(f"{item}\n")


def check_osint_data(url):
    """Given a URL, perform HTTP request to obtain status_code, content_length, content_type, hash(body), timestamp()"""
    extracted_data = None
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, timeout=10, verify=False, headers=headers)

        status_code = response.status_code
        headers = response.headers
        content_type = headers.get('Content-Type', None) if headers else None
        body = response.text
        content_length = len(body)
        
        # Only compute hash if content_type is JavaScript
        hash_value = ''
        if content_type and 'javascript' in content_type.lower():
            hash_value = get_hash(body)
        
        timestamp = get_timestamp()
        extracted_data = {
            'url': url,  # This is the URL that was used to perform the request
            'status_code': status_code,
            'content_length': content_length,
            'content_type': content_type,
            'hash': hash_value,
            'timestamp': timestamp
        }
    except requests.exceptions.Timeout:
        # Don't log every timeout as error - they're expected for dead URLs
        # Only log if it's a connect timeout (server not responding)
        pass
    except requests.exceptions.ConnectionError as e:
        # Connection errors are common for dead/blocked URLs
        pass
    except requests.exceptions.TooManyRedirects:
        write_error(f"OSINT URLs GAU - Fetch URL - Too many redirects for {url}", level='WARNING')
    except requests.exceptions.RequestException as e:
        # Only log unexpected errors
        write_error(f"OSINT URLs GAU - Fetch URL - Error for {url}: {e}", level='WARNING')
    except Exception as e:
        write_error(f"OSINT URLs GAU - Fetch URL - Unexpected error for {url}: {e}", level='WARNING')
    
    return extracted_data


def obtain_passive_data(output_file, program_id):
    """Obtain passive data by fetching URLs"""
    results = []
    num_threads = 40
    try:
        urls = file_to_list(output_file)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Submit all the URL fetch tasks to the executor
            fetch_urls = {executor.submit(check_osint_data, url): url for url in urls}
            
            completed = 0
            for future in concurrent.futures.as_completed(fetch_urls):
                completed += 1
                if completed % 100 == 0:
                    print(f"OSINT URLs GAU - Processed {completed}/{len(urls)} URLs")
                
            
            request_data = future.result()
            if request_data:
                request_data['program_id'] = program_id
                request_data['gathering_method'] = ["passive"]
                results.append(request_data)
        
        print(f"OSINT URLs GAU - Successfully fetched {len(results)}/{len(urls)} URLs")
        
    except Exception as e:
        write_error(f"OSINT URLs GAU - Obtaining passive data - Error: {e}")
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
    urls = params.get('urls', [])
    # For gau, we can also accept domains
    domains = params.get('domains', [])
    
    # Combine urls and domains (gau can work with both)
    input_list = urls + domains
    
    if not input_list:
        write_error("No URLs or domains provided in params.urls or params.domains")
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
    
    # Run passive gathering using gau
    results = {"output": [], "errors": []}
    input_file = ""
    output_file = ""
    
    try:
        # Create temporary files
        input_file = tempfile.mktemp(suffix='.txt')
        output_file = tempfile.mktemp(suffix='.txt')
        
        print(f"OSINT URLs GAU - Storing input in temporary file: {input_file}")
        save_list_to_file(input_list, input_file)
        
        # Use gau to gather URLs
        grep_pattern = EXCLUDED_EXTENSIONS
        cmd = f"cat {input_file} | gau --threads 20 --providers wayback,commoncrawl,otx,urlscan --subs | grep -Ev '{grep_pattern}' | uro | sort -u >>{output_file}"
        
        print(f"OSINT URLs GAU - Running gau for {len(input_list)} inputs")
        process_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            timeout=None  # Use orchestrator timeout
        )
        
        error = process_result.stderr
        if error:
            write_error(f"OSINT URLs GAU - gau stderr: {error}", level='WARNING')
            results['errors'].append(error)
        
        if process_result.returncode != 0:
            write_error(f"OSINT URLs GAU - gau returned non-zero exit code: {process_result.returncode}", level='WARNING')
        
        # From the obtained URLs, perform requests to obtain status_code, content_length, content_type, hash(body), timestamp()
        print(f"OSINT URLs GAU - Data gathered from OSINT sources stored at {output_file}")
        print(f"OSINT URLs GAU - Checking if OSINT data is valid")
        results['output'] = obtain_passive_data(output_file, program_id)
        
    except subprocess.TimeoutExpired:
        write_error("OSINT URLs GAU - gau timeout", level='WARNING')
    except FileNotFoundError:
        write_error("OSINT URLs GAU - gau binary not found. Please ensure gau is installed and in PATH.", level='WARNING')
    except Exception as e:
        write_error(f"OSINT URLs GAU - Error: {e}")
    finally:
        if input_file and os.path.exists(input_file):
            os.remove(input_file)
        if output_file and os.path.exists(output_file):
            os.remove(output_file)
    
    # Write NDJSON output
    records_written = 0
    with open(OUTPUT_FILE, 'w') as out_f:
        for record in results['output']:
            try:
                # Write as NDJSON (one JSON object per line)
                out_f.write(json.dumps(record) + '\n')
                records_written += 1
            except Exception as e:
                write_error(f"Error writing record: {e}")
    
    # Write errors if any
    for error in results['errors']:
        write_error(error, level='WARNING')
    
    if records_written == 0:
        write_error("No URLs gathered", level='WARNING')
    else:
        print(f"OSINT URLs GAU - Found {records_written} URLs")
    
    sys.exit(0)


if __name__ == '__main__':
    print("Running gau (passive URL gathering)")
    main()

