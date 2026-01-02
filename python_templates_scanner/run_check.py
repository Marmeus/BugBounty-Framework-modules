#!/usr/bin/env python3
"""
Helper script to run odin checks locally for debugging.

Usage:
    python3 run_check.py <check_file> --ip <ip> --port <port> --fqdn <fqdn> [--ssl]

Examples:
    python3 run_check.py RECON/backup_files_check.py --ip 192.168.1.1 --port 80 --fqdn example.com
    python3 run_check.py RECON/sensitive_files_check.py --ip 10.0.0.1 --port 443 --fqdn firewall.local --ssl
"""

import sys
import os
import importlib.util
import argparse
from pathlib import Path

# Add the current directory to Python path so odin can be imported
# This ensures odin is found when loading check modules
script_dir = Path(__file__).parent.absolute()
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

def load_check_module(file_path):
    """Load a check module from a file path."""
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Check file not found: {file_path}")
    
    spec = importlib.util.spec_from_file_location("check_module", file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load module from {file_path}")
    
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_module"] = module
    spec.loader.exec_module(module)
    
    # Find the Check class
    if not hasattr(module, 'Check'):
        raise AttributeError(f"Module {file_path} does not have a 'Check' class")
    
    return module.Check

def str_to_bool(value):
    """Convert string to boolean."""
    if isinstance(value, bool):
        return value
    if value.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif value.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError(f'Boolean value expected, got: {value}')

def main():
    parser = argparse.ArgumentParser(
        description='Run a odin check locally for debugging',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('check_file', help='Path to the check file (e.g., RECON/fortios_admin_panel.py)')
    parser.add_argument('--ip', required=True, help='Target IP address')
    parser.add_argument('--port', required=True, type=int, help='Target port number')
    parser.add_argument('--fqdn', required=True, help='Target FQDN')
    parser.add_argument('--ssl', action='store_true', default=False, 
                       help='Use SSL/TLS (default: False)')
    
    args = parser.parse_args()
    
    try:
        # Load the Check class
        Check = load_check_module(args.check_file)
        
        # Import test_check
        from odin import test_check
        
        # Run the check
        print(f'[+] Loading check from: {args.check_file}')
        test_check(Check, args.ip, args.port, args.fqdn, args.ssl)
        
    except Exception as e:
        print(f'[!] Error: {e}', file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

