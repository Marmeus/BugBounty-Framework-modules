#!/usr/bin/env python3
"""
Server Info HTTPX Module - Standalone Entrypoint
Reads task from /task/input.json, runs httpx, captures screenshots with nuclei, writes NDJSON to /task/output.ndjson
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import base64
from pathlib import Path

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'


def write_error(message, level='ERROR'):
    """Write error/warning message to errors file"""
    with open(ERRORS_FILE, 'a') as f:
        f.write(f"[{level}] {message}\n")


def parse_httpx_line(line: str, program_id: int, screenshot_map: dict = None):
    """Parse a single line of httpx JSON output"""
    try:
        data = json.loads(line.strip())
        init_url = data.get('url', None)
        final_url = data.get('final_url', None)
        
        # Try to find screenshot for this URL (prefer final_url, fallback to init_url)
        screenshot_b64 = ''
        if screenshot_map:
            screenshot_b64 = screenshot_map.get(final_url, screenshot_map.get(init_url, ''))
        
        extracted_data = {
            'domain': data.get('input', None),
            'port': data.get('port', None),
            'init_url': init_url,
            'final_url': final_url,
            'location_url': data.get('location', None),
            'title': data.get('title', None),
            'status_code': data.get('status_code', None),
            'chain_status_codes': data.get('chain_status_codes', None),
            'content_length': data.get('content_length', None),
            'cdn_name': data.get('cdn_name', None),
            'webserver': data.get('webserver', None),
            'technologies_list': data.get('tech', None),
            'last_fetched_date': data.get('timestamp', None),
            'screenshot_b64': screenshot_b64,
            'program_id': program_id
        }
        return extracted_data
    except json.JSONDecodeError:
        write_error(f"Failed to parse httpx line: {line[:100]}", level='WARNING')
        return None
    except Exception as e:
        write_error(f"Error parsing httpx line: {e}", level='WARNING')
        return None


def read_httpx_output(output_file: str, program_id: int, screenshot_map: dict = None):
    """Read and parse httpx JSON output file"""
    data = []
    try:
        if not os.path.exists(output_file):
            return data
        
        with open(output_file, 'r') as file:
            for line in file:
                parsed_line = parse_httpx_line(line, program_id, screenshot_map)
                if parsed_line:
                    data.append(parsed_line)
    except Exception as e:
        write_error(f"Error reading httpx output file: {e}")
    return data


def save_domains_to_file(domains: list, domains_file: str):
    """Save domains list to a file (one per line)"""
    try:
        with open(domains_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
    except Exception as e:
        write_error(f"Error saving domains to file: {e}")
        raise


def run_nuclei_screenshot(url: str, timeout: int = 30):
    """Run nuclei screenshot for a single URL and return base64 screenshot"""
    try:
        # Check if nuclei is available
        try:
            result = subprocess.run(['nuclei', '-version'], 
                         capture_output=True, timeout=5, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            write_error(f"Nuclei binary not found. Screenshot skipped for {url}", level='WARNING')
            return ''
        
        # Run nuclei with screenshot capability
        # Nuclei saves screenshots to files, not JSON output
        nuclei_cmd = [
            'nuclei',
            '-u', url,
            '-id', 'screenshot',
            '-headless',
            '-c', '25',
            '-rl', '150',
            '-timeout', '10',
            '-retries', '1',
            '-bs', '25'
        ]
        
        print(f"SERVER_INFO_HTTPX - Capturing screenshot for {url}")
        
        result = subprocess.run(
            nuclei_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Parse output to find screenshot file path
        # Nuclei outputs: "[INF] Screenshot successfully saved at /path/to/screenshot.png"
        screenshot_path = None
        output_text = result.stdout + result.stderr
        
        # Look for the screenshot path in the output
        # Pattern: "Screenshot successfully saved at /path/to/file.png"
        match = re.search(r'(\/app\/screenshots\/.*.png)', output_text)
        if match:
            screenshot_path = match.group(1).strip()
        
        if not screenshot_path or not os.path.exists(screenshot_path):
            write_error(f"Screenshot file not found for {url}. Output: {output_text[:500]}", level='WARNING')
            return ''
        
        # Read the PNG file and convert to base64
        try:
            with open(screenshot_path, 'rb') as f:
                screenshot_bytes = f.read()
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            print(f"SERVER_INFO_HTTPX - Screenshot captured for {url} from {screenshot_path} ({len(screenshot_b64)} chars)")
            
            # Clean up the screenshot file
            try:
                os.remove(screenshot_path)
            except Exception:
                pass  # Ignore cleanup errors
            
            return screenshot_b64
            
        except Exception as e:
            write_error(f"Error reading screenshot file {screenshot_path} for {url}: {e}", level='WARNING')
            return ''
        
    except subprocess.TimeoutExpired:
        write_error(f"Nuclei screenshot timeout for {url}", level='WARNING')
        return ''
    except Exception as e:
        write_error(f"Error capturing screenshot for {url}: {e}", level='WARNING')
        return ''


def run_httpx(domains_file: str, output_file: str, error_file: str):
    """Execute httpx enumeration"""
    try:
        # Check if httpx is available
        try:
            result = subprocess.run(['httpx', '-version'], 
                         capture_output=True, timeout=5, check=True)
            httpx_version = result.stdout.decode() if result.stdout else result.stderr.decode()
            print(f"HTTPX version: {httpx_version}")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            write_error(f"HTTPX binary not found. Please ensure httpx is installed and in PATH.")
            return False
        
        # Get configuration from environment variables
        user_agent = os.getenv('HTTPX_USER_AGENT', os.getenv('USER_AGENT', 'Mozilla/5.0 (Linux; Android 9; ASUS_X00TD; Flow) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/359.0.0.288 Mobile Safari/537.36'))
        ports = os.getenv('HTTPX_PORTS', '80,443,8080,8443,8000,3000,5000')
        # Request timeout (per-request timeout for httpx -timeout flag)
        request_timeout = os.getenv('HTTPX_REQUEST_TIMEOUT', '20')
        delay = os.getenv('HTTPX_DELAY', '200ms')
        threads = os.getenv('HTTPX_THREADS', '100')
        
        # Build httpx command
        # httpx -l domains_file -json -o output_file -silent -nc -ports ... 
        # -H "User-Agent: ..." -timeout ... -delay ... -threads ... 
        # -title -status-code -server -content-length -tech-detect -cdn -follow-host-redirects -follow-redirects
        httpx_cmd = [
            'httpx',
            '-l', domains_file,
            '-json',
            '-o', output_file,
            '-silent',
            '-nc',
            '-ports', ports,
            '-H', f'User-Agent: {user_agent}',
            '-timeout', request_timeout,
            '-delay', delay,
            '-threads', threads,
            '-title',
            '-status-code',
            '-server',
            '-content-length',
            '-tech-detect',
            '-cdn',
            '-follow-host-redirects',
            '-follow-redirects'
        ]
        
        print("SERVER_INFO_HTTPX - Launching httpx")
        print(f"SERVER_INFO_HTTPX - Configuration: ports={ports}, request_timeout={request_timeout}s, delay={delay}, threads={threads}")
        
        # Get overall process timeout from env var (HTTPX_TIMEOUT), default to None (unlimited)
        httpx_timeout = os.getenv('HTTPX_TIMEOUT')
        httpx_timeout = int(httpx_timeout) if httpx_timeout else None
        if httpx_timeout:
            print(f"SERVER_INFO_HTTPX - Process timeout: {httpx_timeout} seconds")
        
        # Execute httpx
        result = subprocess.run(
            httpx_cmd,
            capture_output=True,
            text=True,
            timeout=httpx_timeout
        )
        
        print(f"SERVER_INFO_HTTPX - httpx result:\n{result.stdout}")
        # Check for errors
        if result.stderr:
            error_msg = f"SERVER_INFO_HTTPX - stderr: {result.stderr}"
            write_error(error_msg, level='WARNING')
            with open(error_file, 'a') as f:
                f.write(result.stderr)
        
        if result.returncode != 0:
            error_msg = f"SERVER_INFO_HTTPX - httpx returned non-zero exit code {result.returncode}"
            write_error(error_msg, level='WARNING')
            return False
        
        return True
        
    except subprocess.TimeoutExpired:
        timeout_msg = f"{httpx_timeout} seconds" if httpx_timeout else "configured timeout"
        error_msg = f"SERVER_INFO_HTTPX - httpx timeout after {timeout_msg}"
        write_error(error_msg)
        return False
    except FileNotFoundError:
        error_msg = "SERVER_INFO_HTTPX - httpx binary not found. Please ensure httpx is installed and in PATH."
        write_error(error_msg)
        return False
    except Exception as e:
        error_msg = f"SERVER_INFO_HTTPX - Error: {e}"
        write_error(error_msg)
        return False


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
    
    # Create temporary files
    domains_file = ""
    httpx_output_file = ""
    error_file = ""
    
    try:
        print(f"SERVER_INFO_HTTPX - Starting server info gathering for {len(domains)} domains")
        
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_domains:
            domains_file = tmp_domains.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_output:
            httpx_output_file = tmp_output.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_error:
            error_file = tmp_error.name
        
        # Save domains to file
        save_domains_to_file(domains, domains_file)
        
        # Run httpx
        success = run_httpx(domains_file, httpx_output_file, error_file)
        
        # Read httpx output first to get URLs
        httpx_urls = []
        try:
            if os.path.exists(httpx_output_file):
                with open(httpx_output_file, 'r') as file:
                    for line in file:
                        try:
                            data = json.loads(line.strip())
                            # Collect URLs for screenshot capture (prefer final_url, fallback to url)
                            url = data.get('final_url') or data.get('url')
                            if url and url not in httpx_urls:
                                httpx_urls.append(url)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            write_error(f"Error reading URLs from httpx output: {e}", level='WARNING')
        
        print(f"SERVER_INFO_HTTPX - Found {len(httpx_urls)} unique URLs for screenshot capture")
        
        # Capture screenshots for each URL
        screenshot_map = {}
        screenshot_timeout = int(os.getenv('NUCLEI_SCREENSHOT_TIMEOUT', '30'))
        
        for url in httpx_urls:
            screenshot_b64 = run_nuclei_screenshot(url, timeout=screenshot_timeout)
            if screenshot_b64:
                screenshot_map[url] = screenshot_b64
        
        print(f"SERVER_INFO_HTTPX - Captured {len(screenshot_map)} screenshots")
        
        # Read and parse output with screenshot mapping
        classified_data = read_httpx_output(httpx_output_file, program_id, screenshot_map)
        
        print(f"SERVER_INFO_HTTPX - Found {len(classified_data)} HTTP endpoints")
        
        # Write NDJSON output
        records_written = 0
        with open(OUTPUT_FILE, 'w') as out_f:
            for record in classified_data:
                try:
                    # Write as NDJSON (one JSON object per line)
                    out_f.write(json.dumps(record) + '\n')
                    records_written += 1
                except Exception as e:
                    write_error(f"Error writing record: {e}")
        
        if records_written == 0:
            write_error("No HTTP endpoints found", level='WARNING')
        
        # Read errors from error file if any
        if os.path.exists(error_file):
            with open(error_file, 'r') as f:
                error_content = f.read().strip()
                if error_content:
                    write_error(f"SERVER_INFO_HTTPX - Errors: {error_content}", level='WARNING')
        
    except Exception as e:
        error_msg = f"SERVER_INFO_HTTPX - Error: {e}"
        write_error(error_msg)
        sys.exit(1)
    finally:
        # Clean up temporary files
        if domains_file and os.path.exists(domains_file):
            os.remove(domains_file)
        if httpx_output_file and os.path.exists(httpx_output_file):
            os.remove(httpx_output_file)
        if error_file and os.path.exists(error_file):
            os.remove(error_file)
    
    sys.exit(0)


if __name__ == '__main__':
    print("Running httpx")
    main()

