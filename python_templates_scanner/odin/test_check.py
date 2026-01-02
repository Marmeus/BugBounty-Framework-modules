"""
test_check - Utility function for testing checks locally
"""

from typing import Type
from odin.check_target import CheckTarget
from odin.odin_check import OdinCheck


def test_check(check_class: Type[OdinCheck], ip: str, port: int, fqdn: str, ssl: bool = False):
    """
    Test a check class locally with a given target.
    
    This function creates a CheckTarget, instantiates the check class,
    calls warmup() if it exists, runs the check, and prints the results.
    
    Args:
        check_class: The Check class to test (must be a subclass of OdinCheck)
        ip: IP address of the target
        port: Port number of the target
        fqdn: Fully qualified domain name of the target
        ssl: Whether SSL/TLS is enabled (default: False)
    """
    # Create target
    target = CheckTarget(ip=ip, port=port, fqdn=fqdn, ssl=ssl)
    
    # Run warmup if it exists
    try:
        check_class.warmup()
    except Exception as e:
        print(f'[!] Warning: warmup() failed: {e}')
    
    # Create check instance
    check = check_class(mode='test', target=target)
    
    # Run check
    print(f'[+] Running check on {target.as_url()}')
    try:
        results = check.check()
        
        if not results:
            print('[-] No results found')
        else:
            print(f'[+] Found {len(results)} result(s):')
            for i, result in enumerate(results, 1):
                if isinstance(result, dict):
                    print(f'  [{i}] {result}')
                else:
                    print(f'  [{i}] {result}')
    except Exception as e:
        print(f'[!] Error running check: {e}')
        import traceback
        traceback.print_exc()

