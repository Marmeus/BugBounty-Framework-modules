#!/usr/bin/env python3
"""
Python Templates Scanner Module - Standalone Entrypoint
Reads task from /task/input.json, runs checks using odin library, writes NDJSON to /task/output.ndjson
"""
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, List, Type, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime, timezone

# Import odin library components
from odin.check_target import CheckTarget
from odin.check_result import CheckResult
from odin.odin_check import OdinCheck

# Import check loader
from check_loader import load_all_checks, warmup_checks

# Import Issue class
from issue import Issue

# File paths
INPUT_FILE = '/task/input.json'
OUTPUT_FILE = '/task/output.ndjson'
ERRORS_FILE = '/task/errors.txt'

# Parallel execution settings
# Default max workers: use min of (number of checks, CPU count * 2, 50)
# This prevents too many concurrent connections while still utilizing parallelism
DEFAULT_MAX_WORKERS = min(50, (os.cpu_count() or 1) * 2)

# Thread-safe file writing lock
output_lock = threading.Lock()


def write_error(message: str, level: str = 'ERROR'):
    """Write error/warning message to errors file"""
    with open(ERRORS_FILE, 'a') as f:
        f.write(f"[{level}] {message}\n")


def parse_url_to_target(url: str) -> CheckTarget:
    """
    Parse a URL string into a CheckTarget object
    
    Args:
        url: URL string (e.g., "https://example.com:443" or "http://192.168.1.1:8080")
    
    Returns:
        CheckTarget instance
    """
    parsed = urlparse(url)
    
    # Extract components
    scheme = parsed.scheme or 'http'
    netloc = parsed.netloc or parsed.path
    
    # Determine SSL based on scheme
    ssl = (scheme == 'https')
    
    # Extract host and port
    if ':' in netloc:
        host, port_str = netloc.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443 if ssl else 80
    else:
        host = netloc
        port = 443 if ssl else 80
    
    # Determine if host is IP or FQDN
    # Simple check: if it looks like an IP, use as IP, otherwise as FQDN
    is_ip = all(part.isdigit() for part in host.split('.')) and len(host.split('.')) == 4
    
    if is_ip:
        return CheckTarget(ip=host, port=port, fqdn='', ssl=ssl)
    else:
        return CheckTarget(ip='', port=port, fqdn=host, ssl=ssl)


def convert_to_issue(result: Any, program_id: int, original_url: str, 
                     check_class: Type[OdinCheck] = None) -> Issue:
    """
    Convert a CheckResult or dictionary to an Issue object
    
    Args:
        result: CheckResult object or dictionary
        program_id: Program ID from task
        original_url: Original URL that was checked
        check_class: Check class to extract metadata from (optional)
    
    Returns:
        Issue object
    """
    # Normalize to dictionary: if CheckResult, convert to dict first
    if isinstance(result, CheckResult):
        result_dict = result.to_dict()
    elif isinstance(result, dict):
        result_dict = result
    else:
        raise TypeError(f"Expected CheckResult or dict, got {type(result)}")
    
    # Get URL from result, fallback to original_url if not set
    result_url = result_dict.get('url') or original_url
    
    # Get metadata from result, fallback to check class metadata if available
    name = result_dict.get('name')
    severity = result_dict.get('severity')
    description = result_dict.get('description')
    poc = result_dict.get('poc')
    
    # If metadata not in result, try to get from check class
    if check_class:
        metadata = check_class.get_metadata()
        if not name:
            name = metadata.get('name')
        if not severity:
            severity = metadata.get('severity')
        if not description:
            description = metadata.get('description')
        if not poc:
            poc = metadata.get('poc')
    
    # Set defaults
    if not severity:
        severity = 'Medium'
    if not description:
        description = ''
    
    # Get extra fields that might be in the result
    status_code = result_dict.get('status_code')
    content_length = result_dict.get('content_length', '')
    content_type = result_dict.get('content_type', '')
    
    # Build POC: include result URL and extra fields as JSON if they differ from target or exist
    poc_data = {}
    if result_url != original_url:
        poc_data['url'] = result_url
    
    # If we have extra data or existing POC, combine them
    if poc_data:
        if poc:
            # If there's already a POC, try to parse it and merge, otherwise create a dict
            try:
                existing_poc = json.loads(poc) if isinstance(poc, str) else poc
                if isinstance(existing_poc, dict):
                    poc_data.update(existing_poc)
                    poc = json.dumps(poc_data)
                else:
                    poc = json.dumps(poc_data)
            except (json.JSONDecodeError, TypeError):
                # If POC is not JSON, create a dict with both
                poc = json.dumps({'original_poc': poc, **poc_data})
        else:
            poc = json.dumps(poc_data)
    
    # Get current timestamp for discovered_at
    discovered_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    # Create and return Issue object
    issue = Issue(
        target=original_url,
        name=name,
        severity=severity,
        description=description,
        poc=poc,
        scanner='PythonTemplatesScanner',
        program_id=program_id,
        discovered_at=discovered_at
    )
    
    return issue


def run_single_check(check_class: Type[OdinCheck], target: CheckTarget, url: str, 
                     program_id: int) -> List[Dict[str, Any]]:
    """
    Run a single check against a target and return results.
    
    Args:
        check_class: Check class to run
        target: CheckTarget instance
        url: Original URL string
        program_id: Program ID
    
    Returns:
        List of output dictionaries (from Issue.to_dict())
    """
    results = []
    check_name = check_class.__name__
    
    try:
        # Instantiate the check
        check_instance = check_class(mode='scan', target=target)
        
        # Run the check
        check_results = check_instance.check()
        
        # Convert results to Issue objects, then to dictionaries
        for result in check_results:
            # Handle both CheckResult objects and dictionaries
            if isinstance(result, (CheckResult, dict)):
                try:
                    issue = convert_to_issue(result, program_id, url, check_class)
                    # Convert Issue to dictionary for output
                    results.append(issue.to_dict())
                except TypeError as e:
                    # Skip invalid result types
                    write_error(f"Invalid result type in check {check_name}: {e}", level='WARNING')
                    continue
            else:
                # Skip invalid result types
                continue
    
    except Exception as e:
        # Log error but continue with other checks
        write_error(f"Error running check {check_name} for {url}: {e}", level='WARNING')
    
    return results


def run_checks_for_target(url: str, program_id: int, check_classes: List[Type[OdinCheck]], 
                          max_workers: int = None) -> List[Dict[str, Any]]:
    """
    Run all checks for a given URL in parallel.
    
    Args:
        url: URL to check
        program_id: Program ID
        check_classes: List of Check classes to run
        max_workers: Maximum number of concurrent checks (default: DEFAULT_MAX_WORKERS)
    
    Returns:
        List of output dictionaries
    """
    all_results = []
    
    try:
        # Parse URL to CheckTarget
        target = parse_url_to_target(url)
        
        # Determine max workers
        if max_workers is None:
            max_workers = min(DEFAULT_MAX_WORKERS, len(check_classes))
        
        # Run checks in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all checks
            future_to_check = {
                executor.submit(run_single_check, check_class, target, url, program_id): check_class
                for check_class in check_classes
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_check):
                check_class = future_to_check[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    check_name = check_class.__name__
                    write_error(f"Error in parallel check execution for {check_name} on {url}: {e}", level='WARNING')
    
    except Exception as e:
        write_error(f"Error processing URL {url}: {e}")
    
    return all_results


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
    
    try:
        # Discover and load all checks
        print("PYTHON_TEMPLATES_SCANNER - Discovering checks...")
        check_classes = load_all_checks()
        
        if not check_classes:
            write_error("No checks found in checks directory", level='ERROR')
            sys.exit(1)
        
        print(f"PYTHON_TEMPLATES_SCANNER - Loaded {len(check_classes)} check(s)")
        
        # Warmup checks (if they have warmup methods)
        print("PYTHON_TEMPLATES_SCANNER - Warming up checks...")
        warmup_checks(check_classes)
        
        print(f"PYTHON_TEMPLATES_SCANNER - Starting checks for {len(urls)} service(s)")
        print(f"PYTHON_TEMPLATES_SCANNER - Using parallel execution with max {min(DEFAULT_MAX_WORKERS, len(check_classes))} workers")
        
        # Get max workers from environment variable if set, otherwise use default
        max_workers = None
        if 'ODIN_MAX_WORKERS' in os.environ:
            try:
                max_workers = int(os.environ.get('ODIN_MAX_WORKERS'))
                print(f"PYTHON_TEMPLATES_SCANNER - Using custom max_workers: {max_workers}")
            except ValueError:
                write_error(f"Invalid ODIN_MAX_WORKERS value: {os.environ.get('ODIN_MAX_WORKERS')}", level='WARNING')
        
        # Run checks for each URL
        records_written = 0
        with open(OUTPUT_FILE, 'w') as out_f:
            for url in urls:
                print(f"PYTHON_TEMPLATES_SCANNER - Checking {url}")
                results = run_checks_for_target(url, program_id, check_classes, max_workers=max_workers)
                
                # Write results thread-safely
                for record in results:
                    try:
                        # Write as NDJSON (one JSON object per line)
                        # Record is already a dictionary from Issue.to_dict()
                        with output_lock:
                            out_f.write(json.dumps(record) + '\n')
                        records_written += 1
                    except Exception as e:
                        write_error(f"Error writing record: {e}")
        
        print(f"PYTHON_TEMPLATES_SCANNER - Found {records_written} issue(s)")
        
        if records_written == 0:
            write_error("No issues found", level='WARNING')
    
    except Exception as e:
        error_msg = f"PYTHON_TEMPLATES_SCANNER - Error: {e}"
        write_error(error_msg)
        import traceback
        write_error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == '__main__':
    print("Running Python Templates Scanner")
    main()

