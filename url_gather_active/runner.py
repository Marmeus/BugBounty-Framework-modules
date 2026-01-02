#!/usr/bin/env python3
"""
URL Gather Active Module - Standalone Entrypoint
Reads task from /task/input.json, gathers URLs using katana (active), writes NDJSON to /task/output.ndjson
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import shutil
import hashlib
import requests
from datetime import datetime, timezone
from pathlib import Path
# Disable SSL warnings for unverified HTTPS requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'

# File extensions to exclude
EXCLUDED_EXTENSIONS = r'\.(jpeg|jpg|ttf|woff|woff2|svg|png|ico|css|mp3|gif|mp4|eot|gif|wolf)'

# Maximum body size to hash (10MB) - prevents memory issues with huge responses
MAX_BODY_SIZE_FOR_HASH = 10 * 1024 * 1024


def write_error(message, level='ERROR'):
    """Write error/warning message to errors file"""
    with open(ERRORS_FILE, 'a') as f:
        f.write(f"[{level}] {message}\n")


def get_hash(text):
    """Get SHA256 hash of text"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def get_timestamp():
    """Get current timestamp in ISO format"""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def check_right_url_type(url):
    """Return False if the URL matches excluded extensions"""
    return not re.search(EXCLUDED_EXTENSIONS, url)


def is_javascript_file(url, content_type):
    """Check if URL is a JavaScript file based on extension or content type"""
    if not url:
        return False
    
    # Check by URL extension
    url_lower = url.lower()
    if url_lower.endswith('.js') or url_lower.endswith('.mjs') or url_lower.endswith('.jsx'):
        return True
    
    # Check by content type
    if content_type:
        content_type_lower = content_type.lower()
        if 'javascript' in content_type_lower or 'application/javascript' in content_type_lower or 'text/javascript' in content_type_lower:
            return True
    
    return False


def fetch_javascript_body(url, timeout=30):
    """Fetch JavaScript file body via HTTP request"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=timeout, stream=True)
        response.raise_for_status()
        
        # Read content with size limit to prevent memory issues
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > MAX_BODY_SIZE_FOR_HASH:
                write_error(f"URL Gather Active - JavaScript file too large for {url}, truncating", level='WARNING')
                break
        
        # Decode to string, handling encoding issues
        try:
            body_text = content.decode('utf-8')
        except UnicodeDecodeError:
            # Try with errors='ignore' if UTF-8 fails
            body_text = content.decode('utf-8', errors='ignore')
        
        return body_text
    except requests.exceptions.RequestException as e:
        write_error(f"URL Gather Active - Error fetching JavaScript file {url}: {e}", level='WARNING')
        return None
    except Exception as e:
        write_error(f"URL Gather Active - Unexpected error fetching JavaScript file {url}: {e}", level='WARNING')
        return None


def read_katana_data(line, program_id):
    """Read and parse katana JSON output line"""
    extracted_data = None
    try:
        data = json.loads(line)
        request = data.get('request', None)
        url = None
        if request:
            url = request.get('endpoint', None)
        response = data.get('response', None)
        if response and url and check_right_url_type(url):
            headers = response.get('headers', None)
            status_code = response.get('status_code', None)
            content_type = None
            if headers:
                content_type = headers.get('content_type', None)
            body = response.get('body', "")
            
            content_length = len(body)
            
            # Only calculate hash for JavaScript files
            hash_value = ""
            if is_javascript_file(url, content_type):
                # Fetch JavaScript file body via HTTP request instead of using katana response body
                js_body = fetch_javascript_body(url)
                if js_body:
                    # Limit body size for hashing to prevent memory issues
                    body_for_hash = js_body
                    if len(body_for_hash) > MAX_BODY_SIZE_FOR_HASH:
                        body_for_hash = body_for_hash[:MAX_BODY_SIZE_FOR_HASH]
                        write_error(f"URL Gather Active - JavaScript body too large for {url}, truncating hash input", level='WARNING')
                    
                    hash_value = get_hash(body_for_hash) if body_for_hash else ""
                else:
                    # Fallback to katana response body if HTTP request fails
                    body_for_hash = body
                    if len(body_for_hash) > MAX_BODY_SIZE_FOR_HASH:
                        body_for_hash = body_for_hash[:MAX_BODY_SIZE_FOR_HASH]
                    
                    hash_value = get_hash(body_for_hash) if body_for_hash else ""
            timestamp = get_timestamp()
            extracted_data = {
                'url': url,
                'status_code': status_code,
                'content_type': content_type,
                'content_length': content_length,
                'hash': hash_value,
                'timestamp': timestamp,
                'program_id': program_id,
                'gathering_method': ["active"]
            }
    except json.JSONDecodeError:
        pass  # Skip invalid JSON lines
    except Exception as e:
        write_error(f"URL Gather Active - Error parsing katana data: {e}", level='WARNING')
    return extracted_data


def process_katana_output_file(file_path, program_id, output_file):
    """Process katana output file line-by-line and write results incrementally"""
    records_written = 0
    try:
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return records_written
        
        # Process file line-by-line instead of reading all at once
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                
                extracted_data = read_katana_data(line, program_id)
                if extracted_data:
                    # Write immediately to output file instead of accumulating
                    try:
                        with open(output_file, 'a') as out_f:
                            out_f.write(json.dumps(extracted_data) + '\n')
                        records_written += 1
                    except Exception as e:
                        write_error(f"Error writing record: {e}")
    except Exception as e:
        write_error(f"URL Gather Active - Reading output file {file_path} - Error: {e}")
    return records_written


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
    
    # Run active gathering using katana
    temp_folder = ""
    total_records = 0
    errors = []

    try:
        temp_folder = tempfile.mkdtemp()
        print(f"URL Gather Active - Storing URLs in a temporary folder: {temp_folder}")
        
        # Process each URL with katana and write results incrementally
        for url in urls:
            temp_file = os.path.join(temp_folder, f"{hashlib.md5(url.encode()).hexdigest()}.json")
            print(f"URL Gather Active - Performing URL gathering for url: {url}, results stored at {temp_file}")
            
            # katana command: -u url -j -o output_file -d 5 -silent -jc -kf all -ef jpeg,jpg,svg,png,ico,ttf,tif,tiff,woff,woff2,css,mp3,mp4,eot
            cmd = f"katana -u \"{url}\" -j -o {temp_file} -d 5 -silent -kf all -ef jpeg,jpg,svg,png,ico,ttf,tif,tiff,woff,woff2,css,mp3,mp4,eot"
            
            process_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=None  # Use orchestrator timeout
            )
            
            error = process_result.stderr
            if error:
                write_error(f"URL Gather Active - katana stderr for {url}: {error}", level='WARNING')
                errors.append(error)
            
            if process_result.returncode != 0:
                write_error(f"URL Gather Active - katana returned non-zero exit code {process_result.returncode} for {url}", level='WARNING')
            print(f"URL Gather Active - katana result:\n{process_result.stdout}")
            
            # Process this URL's output immediately and write to final output
            # This prevents accumulating all results in memory
            print(f"URL Gather Active - Processing katana output for {url}")
            records = process_katana_output_file(temp_file, program_id, OUTPUT_FILE)
            total_records += records
            
            # Clean up this URL's temp file immediately to free disk space
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                write_error(f"Error removing temp file {temp_file}: {e}", level='WARNING')
        
    except subprocess.TimeoutExpired:
        write_error("URL Gather Active - katana timeout", level='WARNING')
    except FileNotFoundError:
        write_error("URL Gather Active - katana binary not found. Please ensure katana is installed and in PATH.", level='WARNING')
    except Exception as e:
        write_error(f"URL Gather Active - Error: {e}")
    finally:
        if temp_folder and os.path.exists(temp_folder):
            shutil.rmtree(temp_folder)
    
    # Write errors if any
    for error in errors:
        write_error(error, level='WARNING')
    
    if total_records == 0:
        write_error("No URLs gathered", level='WARNING')
    else:
        print(f"URL Gather Active - Found {total_records} URLs")
    
    sys.exit(0)


if __name__ == '__main__':
    print("Running katana (active URL gathering)")
    main()

