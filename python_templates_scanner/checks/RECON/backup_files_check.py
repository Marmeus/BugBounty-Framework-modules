import os
import json
import base64

from odin import OdinCheck, CheckResult, CheckTarget

import requests
from urllib.parse import urlparse

class Check(OdinCheck):
    # Check metadata
    name = "backup_files_check"
    severity = "Medium"
    description = "Detection of exposed backup files and temporary files on web servers"
    poc = None
    
    def __init__(self, mode: str, target: CheckTarget):
        # keep this line
        super().__init__(mode, target)

        # put your additional initialization code here
        self.backup_extensions = ['.bak', '.bkp', '.backup', '.old', '.ori', '.original', '.tmp', '~']

    def check(self):
        results = []
        # Use SSL flag from target (defaults to False if not set)
        # as_url() will use 'https' if self.target.ssl is True, 'http' otherwise
        base_url = self.target.as_url()
        parsed = urlparse(base_url)
        
        # Extract path parts
        path_parts = [p for p in parsed.path.split('/') if p]  # Remove empty strings
        
        # If the URL has a file extension in the last path component, check for backup files
        if path_parts and '.' in path_parts[-1]:
            # Get the original filename
            original_filename = path_parts[-1]
            
            # Build the base path (directory containing the file)
            # Use the scheme from parsed URL to maintain SSL/TLS setting
            if len(path_parts) > 1:
                dir_path = '/'.join(path_parts[:-1])
                base_path = f"{parsed.scheme}://{parsed.netloc}/{dir_path}"
            else:
                base_path = f"{parsed.scheme}://{parsed.netloc}"
            
            # Check for backup files with different extensions appended to the original filename
            for ext in self.backup_extensions:
                test_url = f"{base_path}/{original_filename}{ext}"
                try:
                    response = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
                    if response.status_code == 200:
                        result = self.create_result(
                            url=test_url,
                            description=f"Possible backup file found: {test_url}",
                            status_code=response.status_code,
                            content_length=response.headers.get('Content-Length', ''),
                            content_type=response.headers.get('Content-Type', '')
                        )
                        results.append(result)
                except requests.exceptions.RequestException:
                    # Silently skip failed requests
                    pass
                except Exception as e:
                    # Log unexpected errors but continue
                    pass
        
        # Also check for common backup filenames at the base URL
        for ext in self.backup_extensions:
            test_url = f"{base_url}/index{ext}"
            try:
                response = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
                if response.status_code == 200:
                    result = self.create_result(
                        url=test_url,
                        description=f"Possible backup file found: {test_url}",
                        status_code=response.status_code
                    )
                    results.append(result)
            except requests.exceptions.RequestException:
                pass
            except Exception as e:
                pass
        
        return results
    
    @staticmethod
    def warmup():
        ### Warming up data
        
        # If you need data to be available to your check in every execution, but retrieving it is costly,
        # you can write that code here.

        # This code will be executed once before running your check against targets. You can store data with:
        
        # Check.set_data('key', value)

        # !! Note the capital C in Check. warmup(), set_data() and get_data() are static class methods.

        pass

# code below this line WILL NOT be executed by odin. it is only useful for you
# to debug your code locally

if __name__ == '__main__':
    import argparse
    from odin import test_check
    
    parser = argparse.ArgumentParser('odin check tester')
    parser.add_argument('--ip', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--ssl', required=False, type=bool, default=False)
    parser.add_argument('--fqdn', required=True)
    args = parser.parse_args()

    test_check(Check, args.ip, args.port, args.fqdn, args.ssl)

