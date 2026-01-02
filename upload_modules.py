#!/usr/bin/env python3
"""
Upload multiple module.yaml files to FRONT API

NOTE: This version disables SSL/TLS certificate verification.
That is insecure and should only be used in trusted dev environments
(e.g., self-signed certs on localhost).
"""

import os
import sys
import glob
import argparse
import requests
import getpass
from pathlib import Path
from typing import List, Tuple, Optional
from urllib.parse import urljoin

# NEW: suppress warnings when verify=False
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_success(message: str):
    """Print success message in green"""
    print(f"{Colors.GREEN}✓{Colors.RESET} {message}")

def print_error(message: str):
    """Print error message in red"""
    print(f"{Colors.RED}✗{Colors.RESET} {message}")

def print_info(message: str):
    """Print info message in cyan"""
    print(f"{Colors.CYAN}ℹ{Colors.RESET} {message}")

def print_warning(message: str):
    """Print warning message in yellow"""
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {message}")

def print_header(message: str):
    """Print header message in bold"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{message}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")


class ModuleUploader:
    """Handles uploading module.yaml files to FRONT"""

    def __init__(self, front_url: str, username: str, password: str, modules_dir: Optional[str] = None):
        """
        Initialize the uploader

        Args:
            front_url: Base URL of FRONT application
            username: Login username
            password: Login password
            modules_dir: Directory containing modules (defaults to script's parent directory)
        """
        self.front_url = front_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()

        # NEW: disable TLS certificate verification for this session
        self.session.verify = False
        urllib3.disable_warnings(InsecureRequestWarning)
        print_warning("SSL/TLS certificate verification is DISABLED (insecure).")

        # Set modules directory - default to parent of script location
        if modules_dir:
            self.modules_dir = Path(modules_dir).resolve()
        else:
            # Default to the directory containing this script
            self.modules_dir = Path(__file__).parent.resolve()

        # Verify modules directory exists
        if not self.modules_dir.exists():
            raise ValueError(f"Modules directory does not exist: {self.modules_dir}")

    def login(self) -> bool:
        """
        Login to FRONT and establish session

        Returns:
            True if login successful, False otherwise
        """
        login_url = urljoin(self.front_url, '/login')

        try:
            print_info(f"Logging in to {self.front_url}...")
            response = self.session.post(
                login_url,
                data={
                    'username': self.username,
                    'password': self.password
                },
                allow_redirects=False,
                timeout=10,
            )

            # Check if login was successful (redirect indicates success)
            if response.status_code == 302:
                print_success("Login successful!")
                return True
            elif response.status_code == 200:
                # If we get 200, login likely failed
                print_error("Login failed: Invalid credentials")
                return False
            else:
                print_error(f"Login failed: Unexpected status code {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            print_error(f"Login failed: {e}")
            return False

    def find_module_yaml_files(self, include_test: bool = False) -> List[Path]:
        """
        Find all module.yaml files in the modules directory

        Args:
            include_test: If True, also include t_module.yaml files

        Returns:
            List of Path objects to module.yaml files
        """
        yaml_files: List[Path] = []

        # Find all module.yaml files
        pattern = str(self.modules_dir / '**' / 'module.yaml')
        yaml_files.extend([Path(f) for f in glob.glob(pattern, recursive=True)])

        # Optionally include test module files
        if include_test:
            pattern = str(self.modules_dir / '**' / 't_module.yaml')
            yaml_files.extend([Path(f) for f in glob.glob(pattern, recursive=True)])

        # Sort for consistent output
        yaml_files.sort()
        return yaml_files

    def upload_module(self, yaml_path: Path) -> Tuple[bool, str, Optional[dict]]:
        """
        Upload a single module.yaml file

        Args:
            yaml_path: Path to the module.yaml file

        Returns:
            Tuple of (success: bool, message: str, response_data: dict or None)
        """
        upload_url = urljoin(self.front_url, '/api/modules/upload')
        module_name = yaml_path.parent.name

        try:
            # Read file
            with open(yaml_path, 'rb') as f:
                files = {
                    'file': (
                        yaml_path.name,
                        f,
                        'application/yaml'
                    )
                }

                response = self.session.post(
                    upload_url,
                    files=files,
                    timeout=30,
                )

            # Parse response
            try:
                response_data = response.json()
            except ValueError:
                response_data = {'status': 'error', 'message': f'HTTP {response.status_code}'}

            if response.status_code == 200 and response_data.get('status') == 'success':
                action = response_data.get('action', 'uploaded')
                message = response_data.get('message', f'Module {action} successfully')
                return True, message, response_data
            else:
                error_msg = response_data.get('message', f'HTTP {response.status_code}')
                return False, error_msg, response_data

        except FileNotFoundError:
            return False, f"File not found: {yaml_path}", None
        except requests.exceptions.RequestException as e:
            return False, f"Network error: {e}", None
        except Exception as e:
            return False, f"Unexpected error: {e}", None

    def upload_all(self, include_test: bool = False, dry_run: bool = False) -> dict:
        """
        Find and upload all module.yaml files

        Args:
            include_test: If True, also upload t_module.yaml files
            dry_run: If True, only show what would be uploaded without actually uploading

        Returns:
            Dictionary with upload results
        """
        yaml_files = self.find_module_yaml_files(include_test=include_test)

        if not yaml_files:
            print_warning(f"No module.yaml files found in {self.modules_dir}")
            return {'total': 0, 'successful': 0, 'failed': 0, 'results': []}

        print_header(f"Found {len(yaml_files)} module.yaml file(s)")
        for yaml_file in yaml_files:
            relative_path = yaml_file.relative_to(self.modules_dir)
            print(f"  • {relative_path}")

        if dry_run:
            print_info("DRY RUN MODE - No files will be uploaded")
            return {'total': len(yaml_files), 'successful': 0, 'failed': 0, 'results': []}

        if not self.login():
            print_error("Cannot proceed without successful login")
            return {'total': len(yaml_files), 'successful': 0, 'failed': len(yaml_files), 'results': []}

        print_header("Uploading modules...")
        results = []
        successful = 0
        failed = 0

        for i, yaml_file in enumerate(yaml_files, 1):
            module_name = yaml_file.parent.name
            relative_path = yaml_file.relative_to(self.modules_dir)

            print(f"\n[{i}/{len(yaml_files)}] Uploading {module_name}...")
            print(f"    File: {relative_path}")

            success, message, response_data = self.upload_module(yaml_file)

            if success:
                print_success(f"{module_name}: {message}")
                successful += 1
            else:
                print_error(f"{module_name}: {message}")
                failed += 1

            results.append({
                'file': str(yaml_file),
                'module_name': module_name,
                'success': success,
                'message': message,
                'response': response_data
            })

        print_header("Upload Summary")
        print(f"Total files:    {len(yaml_files)}")
        print(f"{Colors.GREEN}Successful:    {successful}{Colors.RESET}")
        if failed > 0:
            print(f"{Colors.RED}Failed:        {failed}{Colors.RESET}")

        if failed > 0:
            print(f"\n{Colors.RED}Failed uploads:{Colors.RESET}")
            for result in results:
                if not result['success']:
                    print(f"  • {result['module_name']}: {result['message']}")

        return {
            'total': len(yaml_files),
            'successful': successful,
            'failed': failed,
            'results': results
        }


def prompt_credentials() -> Tuple[str, str]:
    """Prompt for username and password interactively"""
    try:
        print_info("Please enter your FRONT credentials (not stored in history)")
        username = input("Username: ").strip()
        if not username:
            print_error("Username cannot be empty")
            sys.exit(1)

        password = getpass.getpass("Password: ")
        if not password:
            print_error("Password cannot be empty")
            sys.exit(1)

        return username, password
    except (KeyboardInterrupt, EOFError):
        print_error("\nCredential entry cancelled")
        sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Upload multiple module.yaml files to FRONT API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--url',
        dest='front_url',
        default=os.getenv('FRONT_URL', 'https://localhost:5000'),
        help='FRONT application URL (default: from FRONT_URL env var or https://localhost:5000)'
    )

    parser.add_argument(
        '--modules-dir',
        dest='modules_dir',
        default=None,
        help='Directory containing modules (default: directory containing this script)'
    )

    parser.add_argument(
        '--include-test',
        action='store_true',
        help='Also upload t_module.yaml files (test modules)'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be uploaded without actually uploading'
    )

    args = parser.parse_args()

    if not args.dry_run:
        username, password = prompt_credentials()
    else:
        username, password = '', ''

    try:
        uploader = ModuleUploader(
            front_url=args.front_url,
            username=username,
            password=password,
            modules_dir=args.modules_dir
        )
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)

    results = uploader.upload_all(
        include_test=args.include_test,
        dry_run=args.dry_run
    )

    if results['failed'] > 0:
        sys.exit(1)
    elif results['total'] == 0:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
