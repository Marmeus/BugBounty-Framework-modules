#!/usr/bin/env python3
"""
Nuclei Scanner Module - Standalone Entrypoint
Reads task from /task/input.json, runs nuclei with default templates against URLs/domains,
writes NDJSON to /task/output.ndjson
"""
import json
import os
import subprocess
import sys
import tempfile
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


def parse_nuclei_line(line: str, program_id: int):
    """Parse a single line of nuclei JSON output"""
    try:
        vuln = json.loads(line.strip().lstrip().rstrip())
        if 'extracted-results' in vuln:
            vuln['extracted-results'].sort()
            poc = json.dumps(vuln['extracted-results'])
        elif 'meta' in vuln:
            poc = json.dumps(vuln['meta'])
        else:
            poc = ""
        issue = Issue(
            target=vuln['host'],
            name=vuln['info']['name'],
            description=vuln['info']['description'],
            severity=vuln['info']['severity'].lower(),
            poc=poc,
            scanner="nuclei",
            program_id=program_id,
            discovered_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        )
        return issue.to_dict()
    except json.JSONDecodeError:
        write_error(f"Failed to parse nuclei line: {line[:100]}", level='WARNING')
        return None
    except Exception as e:
        write_error(f"Error parsing nuclei line: {e}", level='WARNING')
        return None


def read_nuclei_output(output_file: str, program_id: int):
    """Read and parse nuclei JSON output file"""
    data = []
    try:
        if not os.path.exists(output_file):
            return data
        
        with open(output_file, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                parsed_line = parse_nuclei_line(line, program_id)
                if parsed_line:
                    data.append(parsed_line)
    except Exception as e:
        write_error(f"Error reading nuclei output file: {e}")
    return data


def save_targets_to_file(targets: list, targets_file: str):
    """Save targets list to a file (one per line)"""
    try:
        with open(targets_file, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
    except Exception as e:
        write_error(f"Error saving targets to file: {e}")
        raise




def run_nuclei(targets_file: str, output_file: str):
    """Execute nuclei scanning with default templates"""
    try:
        # Check if nuclei is available
        try:
            result = subprocess.run(['nuclei', '-version'], 
                         capture_output=True, timeout=5, check=True)
            nuclei_version = result.stdout.decode() if result.stdout else result.stderr.decode()
            print(f"NUCLEI_TEMPLATES_SCANNER - Nuclei version: {nuclei_version}")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            write_error("Nuclei binary not found. Please ensure nuclei is installed and in PATH.")
            return False
        
        # Get configuration from environment variables
        rate_limit = os.getenv('NUCLEI_RATE_LIMIT', '150')
        concurrency = os.getenv('NUCLEI_CONCURRENCY', '25')
        timeout = os.getenv('NUCLEI_TIMEOUT', '10')
        retries = os.getenv('NUCLEI_RETRIES', '1')
        severity = os.getenv('NUCLEI_SEVERITY', '')  # Empty means all severities
        tags = os.getenv('NUCLEI_TAGS', '')  # Empty means all tags
        exclude_severity = os.getenv('NUCLEI_EXCLUDE_SEVERITY', '')  # Empty means no exclusion
        exclude_tags = os.getenv('NUCLEI_EXCLUDE_TAGS', '')  # Empty means no exclusion
        templates_path = os.getenv('CUSTOM_NUCLEI_TEMPLATES_PATH', '/root/nuclei-templates')  # By default use nuclei templates
        # Build nuclei command
        # nuclei -l targets_file -json -o output_file -rate-limit ... -c ... -timeout ... -retries ...
        nuclei_cmd = [
            'nuclei',
            '-l', targets_file,
            '-j',
            '-o', output_file,
            '-t', templates_path,
            '-rate-limit', rate_limit,
            '-c', concurrency,
            '-timeout', timeout,
            '-retries', retries,
            '-silent',
            '-no-color'
        ]
        
        # Add severity filter if specified
        if severity:
            nuclei_cmd.extend(['-severity', severity])
        
        # Add tags filter if specified
        if tags:
            nuclei_cmd.extend(['-tags', tags])
        
        # Add exclude-severity filter if specified
        if exclude_severity:
            nuclei_cmd.extend(['-exclude-severity', exclude_severity])
        
        # Add exclude-tags filter if specified
        if exclude_tags:
            nuclei_cmd.extend(['-exclude-tags', exclude_tags])
        
        print("NUCLEI_TEMPLATES_SCANNER - Launching nuclei with default templates")
        print(f"NUCLEI_TEMPLATES_SCANNER - Configuration: rate_limit={rate_limit}, concurrency={concurrency}, timeout={timeout}s, retries={retries}")
        if severity:
            print(f"NUCLEI_TEMPLATES_SCANNER - Severity filter: {severity}")
        if tags:
            print(f"NUCLEI_TEMPLATES_SCANNER - Tags filter: {tags}")
        if exclude_severity:
            print(f"NUCLEI_TEMPLATES_SCANNER - Exclude severity: {exclude_severity}")
        if exclude_tags:
            print(f"NUCLEI_TEMPLATES_SCANNER - Exclude tags: {exclude_tags}")
        
        # Print nuclei command
        print(f"NUCLEI_TEMPLATES_SCANNER - Nuclei command: {' '.join(nuclei_cmd)}")
        
        # Execute nuclei
        result = subprocess.run(
            nuclei_cmd,
            capture_output=True,
            text=True,
            timeout=None  # Use orchestrator timeout
        )
        
        # Check for errors
        if result.stderr:
            error_msg = f"NUCLEI_TEMPLATES_SCANNER - stderr: {result.stderr}"
            write_error(error_msg, level='WARNING')
        
        # Print nuclei result
        print(f"NUCLEI_TEMPLATES_SCANNER - Nuclei result: {result.stdout}")

        if result.returncode != 0:
            error_msg = f"NUCLEI_TEMPLATES_SCANNER - nuclei returned non-zero exit code {result.returncode}"
            write_error(error_msg, level='WARNING')
            # Nuclei may return non-zero even with valid findings, so we continue
        
        return True
        
    except subprocess.TimeoutExpired:
        error_msg = "NUCLEI_TEMPLATES_SCANNER - nuclei timeout"
        write_error(error_msg)
        return False
    except FileNotFoundError:
        error_msg = "NUCLEI_TEMPLATES_SCANNER - nuclei binary not found. Please ensure nuclei is installed and in PATH."
        write_error(error_msg)
        return False
    except Exception as e:
        error_msg = f"NUCLEI_TEMPLATES_SCANNER - Error: {e}"
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
    urls = params.get('urls', [])
    domains = params.get('domains', [])
    
    # Combine urls and domains, normalize to URLs
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
    
    # Create temporary files
    targets_file = ""
    nuclei_output_file = ""
    
    try:
        print(f"NUCLEI_TEMPLATES_SCANNER - Starting nuclei scan for {len(input_list)} targets")
        
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_targets:
            targets_file = tmp_targets.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_output:
            nuclei_output_file = tmp_output.name
        
        # Save targets to file
        save_targets_to_file(input_list, targets_file)
        
        # Run nuclei
        success = run_nuclei(targets_file, nuclei_output_file)
        
        # Read and parse output
        scan_results = read_nuclei_output(nuclei_output_file, program_id)
        
        print(f"NUCLEI_TEMPLATES_SCANNER - Found {len(scan_results)} vulnerabilities")
        
        # Write NDJSON output
        records_written = 0
        with open(OUTPUT_FILE, 'w') as out_f:
            for record in scan_results:
                try:
                    # Write as NDJSON (one JSON object per line)
                    out_f.write(json.dumps(record) + '\n')
                    records_written += 1
                except Exception as e:
                    write_error(f"Error writing record: {e}")
        
        if records_written == 0:
            write_error("No vulnerabilities found", level='WARNING')
        else:
            print(f"NUCLEI_TEMPLATES_SCANNER - Wrote {records_written} vulnerability records")
        
    except Exception as e:
        error_msg = f"NUCLEI_TEMPLATES_SCANNER - Error: {e}"
        write_error(error_msg)
        sys.exit(1)
    finally:
        # Clean up temporary files
        if targets_file and os.path.exists(targets_file):
            os.remove(targets_file)
        if nuclei_output_file and os.path.exists(nuclei_output_file):
            os.remove(nuclei_output_file)
    
    sys.exit(0)


if __name__ == '__main__':
    print("Running nuclei scanner with default templates")
    main()

