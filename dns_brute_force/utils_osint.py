"""
Utility functions for OSINT modules
Based on WORKER/Docker/bot/UTILS/utils.py
"""
import subprocess
import os
import shutil
import re


def create_random_file(route="/tmp/"):
    """Create a random temporary file"""
    result = ""
    process_result = subprocess.run([f"mktemp -p {route}"], capture_output=True, text=True, shell=True)
    result = process_result.stdout[:-1]
    error = process_result.stderr
    if process_result.returncode != 0 or error:
        raise RuntimeError(f"Error creating random file: {error}")
    return result


def create_random_folder(route="/tmp/"):
    """Create a random temporary folder"""
    result = ""
    process_result = subprocess.run([f"mktemp -d -p {route}"], capture_output=True, text=True, shell=True)
    result = process_result.stdout[:-1]
    error = process_result.stderr
    if process_result.returncode != 0 or error:
        raise RuntimeError(f"Error creating random folder: {error}")
    return result


def remove_folder(folder_path):
    """Remove a folder if it exists"""
    if folder_path and os.path.exists(folder_path):
        shutil.rmtree(folder_path)
    return


def remove_file(file_path):
    """Remove a file if it exists"""
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
    return


def detect_domain_level(domain):
    """Detect domain level based on number of dots (excluding TLD)
    Returns: number of subdomain levels
    Example: 'sub.example.com' = 1, 'sub.sub.example.com' = 2
    """
    domain_parts = domain.split('.')
    domain_parts = domain_parts[:-1]  # Remove TLD
    return len(domain_parts)


def check_scope(domain, in_scope_rules, out_scope_rules):
    """Check if domain matches scope rules
    
    Args:
        domain: Domain to check
        in_scope_rules: List of in-scope patterns
        out_scope_rules: List of out-of-scope patterns
    
    Returns:
        True if in scope, False if out of scope
    """
    # Check if the domain matches any of the out-of-scope rules
    if out_scope_rules:
        for rule in out_scope_rules:
            if rule and re.match(rule.replace('.', r'\.').replace('*', r'.*'), domain):
                return False

    # Check if the domain matches any of the in-scope rules
    if in_scope_rules:
        for rule in in_scope_rules:
            if rule and re.match(rule.replace('.', r'\.').replace('*', r'.*'), domain):
                return True

    # If the domain doesn't match any in-scope rule and isn't explicitly out of scope, consider it in scope
    return True


def read_errors(error_file):
    """Read error file content"""
    if not error_file or not os.path.exists(error_file):
        return None
    try:
        with open(error_file, 'r') as file:
            error_content = file.readlines()
        return ''.join(error_content) if error_content else None
    except Exception:
        return None


def save_list_to_file(items, file_path):
    """Save list of items to file (one per line)"""
    with open(file_path, 'w') as f:
        for item in items:
            f.write(f"{item}\n")


def file_to_list(file_path):
    """Read file and return list of lines (stripped)"""
    if not file_path or not os.path.exists(file_path):
        return []
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []

